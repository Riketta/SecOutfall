// D3 injection engine implementation. See Injection.h for the design and
// the accepted v1 limits. Every failure path is counted; nothing here can
// block a hook path (the engine runs off process/thread/image-notify and
// IOCTL contexts only).
//
// Lock discipline: the ledger FastMutex only guards ledger membership and
// state transitions. The injection itself (KeStackAttachProcess + user-memory
// writes) cannot run under a FastMutex (attach is APC-max), so it happens
// with EXTRA references taken under the lock — the entry or the thread may
// exit mid-injection and the attempt fails harmlessly, counted.

#include "pch.h"
#include <ntimage.h>
#include "Memory.h"

// Exported by ntoskrnl but absent from the public headers.
extern "C" NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
	_In_ PEPROCESS SourceProcess, _In_ const VOID* SourceAddress,
	_In_ PEPROCESS TargetProcess, _Out_ VOID* TargetAddress,
	_In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
	_Out_ PSIZE_T ReturnSize);

// The APC machinery is equally undocumented. Shapes match the internal
// ntoskrnl interfaces every kernel injector uses.
typedef VOID (*PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1,
	PVOID SystemArgument2);
typedef VOID (*PKKERNEL_ROUTINE)(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef VOID (*PKRUNDOWN_ROUTINE)(PKAPC Apc);

// Absent from ntifs alongside the APC routines (KeUnstackDetachProcess
// itself IS declared there — only the APC trio needs manual declarations).
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

extern "C" NTKERNELAPI VOID KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PRKTHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext);

extern "C" NTKERNELAPI BOOLEAN KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment);

#include "Injection.h"
#include "secoutfall.h"
#include "secoutfallCommon.h"

namespace {

// Compiled blocklist — always applied, before any policy exclusions. System
// (pid 4) and the idle process are skipped by pid, not by name.
const PWCHAR DefaultBlocklist[] = {
	L"smss.exe",
	L"csrss.exe",
	L"wininit.exe",
	L"winlogon.exe",
	L"services.exe",
	L"lsass.exe",
	L"secoutfall-agent.exe",
	L"secoutfall-user-actor.exe",
	L"dump.exe",
};

InjectionEntry* FindLedgerEntryLocked(_In_ ULONG pid) {
	for (auto link = g_Data.InjectionLedger.Flink; link != &g_Data.InjectionLedger; link = link->Flink) {
		auto entry = CONTAINING_RECORD(link, InjectionEntry, Link);
		if (entry->Pid == pid)
			return entry;
	}
	return nullptr;
}

void RemoveLedgerEntryLocked(_In_ InjectionEntry* entry) {
	RemoveEntryList(&entry->Link);
	g_Data.InjectionLedgerCount--;
	if (entry->InitialThread)
		ObDereferenceObject(entry->InitialThread);
	entry->InitialThread = nullptr;
	ExFreePool(entry);
}

// Resolves LdrLoadDll's RVA by walking the export directory of the mapped
// ntdll image. Runs in the image-load callback, in the loading process's
// context; the mapped PE is read via MmCopyVirtualMemory into kernel buffers
// (the pages belong to a freshly mapped system DLL, but nothing is trusted).
bool ResolveLdrLoadDllRva(_In_ PVOID ntdllBase, _Out_ ULONG* rva) {
	*rva = 0;

	// Headers first.
	UCHAR headerPage[4096];
	PEPROCESS process = PsGetCurrentProcess();
	SIZE_T copied = 0;
	auto status = ::MmCopyVirtualMemory(process, ntdllBase, process, headerPage,
		sizeof(headerPage), KernelMode, &copied);
	if (!NT_SUCCESS(status) || copied != sizeof(headerPage))
		return false;

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(headerPage);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	auto ntRva = dos->e_lfanew;
	if (ntRva <= 0 || ntRva + sizeof(IMAGE_NT_HEADERS64) > sizeof(headerPage))
		return false;
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(headerPage + ntRva);
	if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return false;

	auto exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.VirtualAddress == 0 || exportDir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
		return false;

	IMAGE_EXPORT_DIRECTORY dir = {};
	status = ::MmCopyVirtualMemory(process,
		reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntdllBase) + exportDir.VirtualAddress),
		process, &dir, sizeof(dir), KernelMode, &copied);
	if (!NT_SUCCESS(status) || copied != sizeof(dir))
		return false;
	if (dir.NumberOfNames == 0 || dir.NumberOfNames > 100000)
		return false;

	auto nameRVAs = (PULONG)::ExAllocatePool2(POOL_FLAG_PAGED,
		ULONGLONG(dir.NumberOfNames) * 4, DRIVER_TAG);
	if (nameRVAs == nullptr)
		return false;
	status = ::MmCopyVirtualMemory(process,
		reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntdllBase) + dir.AddressOfNames),
		process, nameRVAs, ULONGLONG(dir.NumberOfNames) * 4, KernelMode, &copied);
	if (!NT_SUCCESS(status) || copied != ULONGLONG(dir.NumberOfNames) * 4) {
		ExFreePool(nameRVAs);
		return false;
	}

	auto found = false;
	static const char target[] = "LdrLoadDll";
	for (ULONG i = 0; i < dir.NumberOfNames; ++i) {
		char name[32] = {};
		status = ::MmCopyVirtualMemory(process,
			reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntdllBase) + nameRVAs[i]),
			process, name, sizeof(name) - 1, KernelMode, &copied);
		if (!NT_SUCCESS(status))
			continue;
		if (::strncmp(name, target, sizeof(target) - 1) != 0)
			continue;
		// name -> ordinal index -> function RVA
		USHORT ordinalIndex = 0;
		status = ::MmCopyVirtualMemory(process,
			reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntdllBase)
				+ dir.AddressOfNameOrdinals + ULONGLONG(i) * 2),
			process, &ordinalIndex, sizeof(ordinalIndex), KernelMode, &copied);
		if (!NT_SUCCESS(status) || copied != sizeof(ordinalIndex))
			break;
		ULONG functionRva = 0;
		status = ::MmCopyVirtualMemory(process,
			reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntdllBase)
				+ dir.AddressOfFunctions + ULONGLONG(ordinalIndex) * 4),
			process, &functionRva, sizeof(functionRva), KernelMode, &copied);
		if (!NT_SUCCESS(status) || copied != sizeof(functionRva) || functionRva == 0)
			break;
		*rva = functionRva;
		found = true;
		break;
	}

	ExFreePool(nameRVAs);
	return found;
}

bool ImageNameSuffixIs(_In_ PCUNICODE_STRING name, _In_ PCWSTR suffix) {
	auto suffixLen = static_cast<USHORT>(wcslen(suffix) * sizeof(WCHAR));
	if (name->Length < suffixLen)
		return false;
	UNICODE_STRING tail;
	tail.Buffer = name->Buffer + (name->Length - suffixLen) / sizeof(WCHAR);
	tail.Length = suffixLen;
	tail.MaximumLength = suffixLen;
	UNICODE_STRING other;
	other.Buffer = const_cast<PWCHAR>(suffix);
	other.Length = suffixLen;
	other.MaximumLength = suffixLen;
	return ::RtlEqualUnicodeString(&tail, &other, TRUE);
}

// The target-side stub: bridges the user-APC single argument to LdrLoadDll's
// four. rcx arrives pointing at the argument block laid out as
//   [0x00] UNICODE_STRING*  module name
//   [0x08] HANDLE*          out handle
//   [0x10] LdrLoadDll       address
// 20 bytes, position-independent, no stack use:
//   48 89 C8        mov  rax, rcx
//   31 C9           xor  ecx, ecx            ; SearchPath = NULL
//   31 D2           xor  edx, edx            ; Flags = NULL
//   4C 8B 00        mov  r8,  [rax]          ; UNICODE_STRING*
//   4C 8B 48 08     mov  r9,  [rax+8]        ; HANDLE*
//   48 8B 40 10     mov  rax, [rax+0x10]     ; LdrLoadDll
//   FF E0           jmp  rax
const UCHAR InjectStubBytes[] = {
	0x48, 0x89, 0xC8, 0x31, 0xC9, 0x31, 0xD2,
	0x4C, 0x8B, 0x00, 0x4C, 0x8B, 0x48, 0x08,
	0x48, 0x8B, 0x40, 0x10, 0xFF, 0xE0,
};

void InjectKernelRoutine(_In_ PKAPC apc, _Inout_ PKNORMAL_ROUTINE* normalRoutine,
	_Inout_ PVOID* normalContext, _Inout_ PVOID* systemArgument1, _Inout_ PVOID* systemArgument2) {
	UNREFERENCED_PARAMETER(normalRoutine);
	UNREFERENCED_PARAMETER(normalContext);
	UNREFERENCED_PARAMETER(systemArgument1);
	UNREFERENCED_PARAMETER(systemArgument2);
	ExFreePool(apc);
}

// Queues the user APC. The argument block and the stub live in the target
// and die with it (user pages) — nothing to free kernel-side except the KAPC,
// which the kernel routine releases on delivery.
bool QueueLoadLibraryApc(_In_ PEPROCESS process, _In_ PETHREAD thread,
	_In_ PCUNICODE_STRING dllPath, _In_ PVOID ntdllBase, _In_ ULONG ldrLoadDllRva) {
	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	auto ok = false;
	PVOID block = nullptr;
	PVOID stub = nullptr;
	SIZE_T blockSize = 0x40 + dllPath->Length + sizeof(HANDLE);
	SIZE_T stubSize = sizeof(InjectStubBytes);

	do {
		auto status = ::ZwAllocateVirtualMemory(NtCurrentProcess(), &block, 0, &blockSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(status))
			break;

		status = ::ZwAllocateVirtualMemory(NtCurrentProcess(), &stub, 0, &stubSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			stub = nullptr;
			break;
		}

		// Argument block:
		//   +0x00 UNICODE_STRING*   +0x08 HANDLE*   +0x10 LdrLoadDll
		//   +0x18 UNICODE_STRING    +0x28 HANDLE    +0x30 wide path
		auto base = static_cast<PUCHAR>(block);
		auto pathAddr = base + 0x30;
		auto unicodeAddr = base + 0x18;
		auto handleAddr = base + 0x28;
		*reinterpret_cast<PVOID*>(base + 0x00) = unicodeAddr;
		*reinterpret_cast<PVOID*>(base + 0x08) = handleAddr;
		*reinterpret_cast<PVOID*>(base + 0x10) = reinterpret_cast<PVOID>(
			reinterpret_cast<ULONG_PTR>(ntdllBase) + ldrLoadDllRva);
		auto unicode = reinterpret_cast<PUNICODE_STRING>(unicodeAddr);
		unicode->Length = dllPath->Length;
		unicode->MaximumLength = dllPath->Length + sizeof(WCHAR);
		unicode->Buffer = reinterpret_cast<PWCH>(pathAddr);
		::memcpy(pathAddr, dllPath->Buffer, dllPath->Length);
		*reinterpret_cast<HANDLE*>(handleAddr) = nullptr;
		::memcpy(stub, InjectStubBytes, sizeof(InjectStubBytes));

		auto apc = (PKAPC)::ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG);
		if (apc == nullptr)
			break;

		::KeInitializeApc(apc, thread, OriginalApcEnvironment, InjectKernelRoutine,
			nullptr, reinterpret_cast<PKNORMAL_ROUTINE>(stub), UserMode, block);
		if (!::KeInsertQueueApc(apc, nullptr, nullptr, IO_NO_INCREMENT)) {
			ExFreePool(apc);
			break;
		}
		ok = true;
	} while (false);

	KeUnstackDetachProcess(&apcState);
	return ok;
}

// Queues the sensor-load APC for a ledger entry SNAPSHOT: thread + ntdll
// base are copies taken under the lock. Runs WITHOUT the ledger lock and
// never touches the entry — a concurrent process exit (RemoveLedgerEntryLocked
// ExFreePools the entry) must not turn this into a use-after-free.
// Caller holds: one extra thread reference, one process reference.
// IRQL <= APC_LEVEL (QueueLoadLibraryApc attaches to the target process).
bool TryInjectSnapshot(_In_ PETHREAD thread, _In_ PEPROCESS process,
	_In_ PVOID ntdllBase) {
	if (!g_Data.LdrLoadDllRvaResolved || g_Data.SensorDllPath.Buffer == nullptr) {
		return false;
	}
	return QueueLoadLibraryApc(process, thread, &g_Data.SensorDllPath,
		ntdllBase, g_Data.LdrLoadDllRva);
}

// Fires the injection attempt from the notify hooks. Must be called WITH the
// ledger lock held; temporarily RELEASES it. Two hard contract rules the
// review found violated here:
// 1. PsLookupProcessByProcessId is PASSIVE_LEVEL-only, and this function
//    runs at DISPATCH under the FastMutex — Driver Verifier bugcheck class.
// 2. After dropping the lock the raw entry pointer is UNPROTECTED: a
//    concurrent process exit frees it. Everything the APC needs is snapshotted
//    into locals BEFORE the unlock, and the post-attempt state fixup re-finds
//    the LIVE entry instead of dereferencing the stale one.
void TryInjectLocked(_In_ InjectionEntry* entry, _In_ ULONG pid) {
	if (entry->InitialThread == nullptr || entry->NtdllBase == nullptr
		|| !g_Data.LdrLoadDllRvaResolved || !g_Data.InjectionEnabled
		|| g_Data.SensorDllPath.Buffer == nullptr)
		return;

	// Transition Pending* -> Injected claims the attempt; the fixup below
	// rolls it back on failure so a later trigger can retry.
	auto previous = InterlockedCompareExchange(
		reinterpret_cast<volatile LONG*>(&entry->State),
		LONG(InjectionState::Injected), LONG(InjectionState::PendingNtdll));
	if (previous != LONG(InjectionState::PendingNtdll))
		return;

	// Snapshot under the lock: thread reference + ntdll base. The ENTRY has
	// no extra reference — after Unlock it may be freed (that is exactly
	// why this copy exists).
	ObReferenceObject(entry->InitialThread);
	auto thread = entry->InitialThread;
	auto ntdllBase = entry->NtdllBase;

	// PASSIVE_LEVEL from here: safe for PsLookupProcessByProcessId and for
	// the process attach inside QueueLoadLibraryApc.
	g_Data.InjectionLedgerLock->Unlock();

	PEPROCESS process = nullptr;
	auto status = ::PsLookupProcessByProcessId(
		reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &process);
	auto lookupOk = NT_SUCCESS(status);
	auto ok = lookupOk && TryInjectSnapshot(thread, process, ntdllBase);

	if (process != nullptr)
		ObDereferenceObject(process);
	ObDereferenceObject(thread);

	// State fixup on the LIVE entry (the stale pointer may already be freed
	// — or, worst case, the pid reused by a fresh entry; either way the
	// re-find decides, never the stale pointer).
	g_Data.InjectionLedgerLock->Lock();
	auto current = FindLedgerEntryLocked(pid);
	if (current == nullptr)
		return;
	if (ok) {
		InterlockedIncrement64(&g_Data.InjectionsQueued);
	} else if (!lookupOk) {
		// Process already gone (or unknown): retryable — a later trigger is
		// meaningless for THIS process, but keeping Pending preserves the
		// pre-review claim semantics and the counters stay honest.
		InterlockedExchange(reinterpret_cast<volatile LONG*>(&current->State),
			LONG(InjectionState::PendingNtdll));
	} else {
		// APC queue failure is terminal for the attempt (matches the old
		// Failed state); Failed is scored as a sensor-degradation signal.
		InterlockedExchange(reinterpret_cast<volatile LONG*>(&current->State),
			LONG(InjectionState::Failed));
		InterlockedIncrement64(&g_Data.InjectionsFailed);
	}
}

} // namespace

void InjectionInit() {
	InitializeListHead(&g_Data.InjectionLedger);
	g_Data.InjectionLedgerCount = 0;
	g_Data.InjectionEnabled = false;
	g_Data.LdrLoadDllRvaResolved = false;
	g_Data.SensorDllPath.Buffer = nullptr;
	g_Data.SensorDllPath.Length = 0;
	g_Data.SensorDllPath.MaximumLength = 0;

	g_Data.InjectionLedgerLock = new (NonPagedPool) FastMutex;
	g_Data.InjectionBlocklist = new (NonPagedPool) FileWatch;
	g_Data.InjectionExtraBlocklist = new (NonPagedPool) FileWatch;
	if (!g_Data.InjectionLedgerLock || !g_Data.InjectionBlocklist || !g_Data.InjectionExtraBlocklist)
		return;

	g_Data.InjectionBlocklist->Init();
	g_Data.InjectionExtraBlocklist->Init();

	// Compiled defaults into the always-on blocklist.
	ULONG count = RTL_NUMBER_OF(DefaultBlocklist);
	ULONG blobBytes = 0;
	for (ULONG i = 0; i < count; ++i)
		blobBytes += static_cast<ULONG>((wcslen(DefaultBlocklist[i]) + 1) * sizeof(WCHAR));
	auto blob = (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED, blobBytes, DRIVER_TAG);
	auto exts = (PUNICODE_STRING*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
		sizeof(PUNICODE_STRING) * count, DRIVER_TAG);
	if (blob == nullptr || exts == nullptr) {
		if (blob) ExFreePool(blob);
		if (exts) ExFreePool(exts);
		return;
	}
	ULONG index = 0;
	auto cursor = blob;
	for (ULONG i = 0; i < count; ++i) {
		auto len = static_cast<ULONG>(wcslen(DefaultBlocklist[i]) * sizeof(WCHAR));
		auto entry = (PUNICODE_STRING)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
			sizeof(UNICODE_STRING), DRIVER_TAG);
		if (entry == nullptr)
			continue;
		::memcpy(cursor, DefaultBlocklist[i], len);
		cursor[len / sizeof(WCHAR)] = L'\0';
		entry->Buffer = cursor;
		entry->Length = static_cast<USHORT>(len);
		entry->MaximumLength = entry->Length;
		exts[index] = entry;
		++index;
		cursor += len / sizeof(WCHAR) + 1;
	}
	g_Data.InjectionBlocklist->Apply(true, exts, index, blob,
		static_cast<ULONG>(cursor - blob) * sizeof(WCHAR));
}

void InjectionCleanup() {
	// Detach the ledger under the lock, then unwind outside: entry teardown
	// closes handles (ZwClose is PASSIVE/APC-only, never DISPATCH).
	LIST_ENTRY dead;
	if (g_Data.InjectionLedgerLock) {
		AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
		InitializeListHead(&dead);
		AppendTailList(&dead, &g_Data.InjectionLedger);
		InitializeListHead(&g_Data.InjectionLedger);
		g_Data.InjectionLedgerCount = 0;
	}
	while (!IsListEmpty(&dead)) {
		auto link = RemoveHeadList(&dead);
		RemoveLedgerEntryLocked(CONTAINING_RECORD(link, InjectionEntry, Link));
	}
	if (g_Data.InjectionBlocklist) {
		delete g_Data.InjectionBlocklist;
		g_Data.InjectionBlocklist = nullptr;
	}
	if (g_Data.InjectionExtraBlocklist) {
		delete g_Data.InjectionExtraBlocklist;
		g_Data.InjectionExtraBlocklist = nullptr;
	}
	if (g_Data.InjectionLedgerLock) {
		delete g_Data.InjectionLedgerLock;
		g_Data.InjectionLedgerLock = nullptr;
	}
	if (g_Data.SensorDllPath.Buffer) {
		ExFreePool(g_Data.SensorDllPath.Buffer);
		g_Data.SensorDllPath.Buffer = nullptr;
	}
}

bool InjectionSetPolicy(_In_ bool enabled, _In_ PCUNICODE_STRING dllPath,
	_In_opt_ PCUNICODE_STRING extraExclusions) {
	// New path buffer first: allocation failure keeps the old policy.
	PWCHAR pathBuffer = nullptr;
	if (dllPath->Length > 0) {
		pathBuffer = (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
			dllPath->Length + sizeof(WCHAR), DRIVER_TAG);
		if (pathBuffer == nullptr)
			return false;
		::memcpy(pathBuffer, dllPath->Buffer, dllPath->Length);
		pathBuffer[dllPath->Length / sizeof(WCHAR)] = L'\0';
	}

	if (extraExclusions && extraExclusions->Length >= sizeof(WCHAR)) {
		ULONG count = 0;
		ULONG offset = 0;
		while (offset + sizeof(WCHAR) <= extraExclusions->Length) {
			ULONG len = 0;
			auto cursor = extraExclusions->Buffer + offset / sizeof(WCHAR);
			while (offset + (len + 1) * sizeof(WCHAR) <= extraExclusions->Length
				&& cursor[len] != L'\0')
				++len;
			if (len == 0)
				break;
			++count;
			offset += (len + 1) * sizeof(WCHAR);
		}
		auto exts = count > 0
			? (PUNICODE_STRING*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
				sizeof(PUNICODE_STRING) * count, DRIVER_TAG)
			: nullptr;
		auto blob = count > 0
			? (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED, extraExclusions->Length, DRIVER_TAG)
			: nullptr;
		if (count > 0 && (exts == nullptr || blob == nullptr)) {
			if (exts) ExFreePool(exts);
			if (blob) ExFreePool(blob);
			if (pathBuffer) ExFreePool(pathBuffer);
			return false;
		}
		ULONG index = 0;
		offset = 0;
		while (offset + sizeof(WCHAR) <= extraExclusions->Length && index < count) {
			ULONG len = 0;
			auto cursor = extraExclusions->Buffer + offset / sizeof(WCHAR);
			while (offset + (len + 1) * sizeof(WCHAR) <= extraExclusions->Length
				&& cursor[len] != L'\0')
				++len;
			if (len == 0)
				break;
			auto entry = (PUNICODE_STRING)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
				sizeof(UNICODE_STRING), DRIVER_TAG);
			if (entry == nullptr)
				break;
			::memcpy(blob + offset / sizeof(WCHAR), cursor, len * sizeof(WCHAR));
			blob[offset / sizeof(WCHAR) + len] = L'\0';
			entry->Buffer = blob + offset / sizeof(WCHAR);
			entry->Length = static_cast<USHORT>(len * sizeof(WCHAR));
			entry->MaximumLength = entry->Length;
			exts[index] = entry;
			++index;
			offset += (len + 1) * sizeof(WCHAR);
		}
		g_Data.InjectionExtraBlocklist->Apply(true, exts, index, blob,
			extraExclusions->Length);
	}

	if (g_Data.SensorDllPath.Buffer)
		ExFreePool(g_Data.SensorDllPath.Buffer);
	g_Data.SensorDllPath.Buffer = pathBuffer;
	g_Data.SensorDllPath.Length = pathBuffer ? dllPath->Length : 0;
	g_Data.SensorDllPath.MaximumLength = g_Data.SensorDllPath.Length;
	g_Data.InjectionEnabled = enabled && pathBuffer != nullptr;
	return true;
}

bool InjectionWantsProcess(_In_ ULONG pid, _In_opt_ PCUNICODE_STRING imageFileName) {
	if (!g_Data.InjectionEnabled || pid <= 4)
		return false;
	if (imageFileName != nullptr) {
		if (g_Data.InjectionBlocklist && g_Data.InjectionBlocklist->Matches(imageFileName))
			return false;
		if (g_Data.InjectionExtraBlocklist && g_Data.InjectionExtraBlocklist->Matches(imageFileName))
			return false;
	}
	return true;
}

void InjectionOnProcessCreate(_In_ ULONG pid, _In_ ULONG64 createTime,
	_In_opt_ PCUNICODE_STRING imageFileName) {
	if (!InjectionWantsProcess(pid, imageFileName))
		return;

	// Nonce: kernel tick mixed with pid and a counter — the ledger gate does
	// the heavy lifting, the nonce defeats casual impersonation.
	ULONG64 tick = 0;
	KeQueryTickCount(reinterpret_cast<PLARGE_INTEGER>(&tick));
	ULONG64 nonce = tick * 0x9E3779B97F4A7C15ull ^ (ULONGLONG(pid) << 32)
		^ InterlockedIncrement64(&g_Data.InjectionsQueued);

	auto entry = (InjectionEntry*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
		sizeof(InjectionEntry), DRIVER_TAG);
	if (entry == nullptr) {
		InterlockedIncrement64(&g_Data.AllocFailures);
		return;
	}
	entry->Pid = pid;
	entry->CreateTime = createTime;
	entry->Nonce = nonce;
	entry->InitialThread = nullptr;
	entry->ProcessHandle = nullptr;
	entry->NtdllBase = nullptr;
	entry->State = InjectionState::PendingThread;

	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	if (FindLedgerEntryLocked(pid) != nullptr) {
		ExFreePool(entry);
		return;
	}
	InsertTailList(&g_Data.InjectionLedger, &entry->Link);
	g_Data.InjectionLedgerCount++;
}

void InjectionOnFirstThread(_In_ ULONG pid, _In_ PETHREAD thread) {
	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	auto entry = FindLedgerEntryLocked(pid);
	if (entry == nullptr)
		return;
	if (entry->InitialThread == nullptr) {
		ObReferenceObject(thread);
		entry->InitialThread = thread;
	}
	TryInjectLocked(entry, pid);
}

void InjectionOnImageLoad(_In_ ULONG pid, _In_ PVOID base, _In_ PCUNICODE_STRING fullImageName) {
	// One-time: resolve LdrLoadDll's RVA from the first ntdll mapped after
	// the driver loaded. Exact case-insensitive suffix: "\ntdll.dll".
	if (!g_Data.LdrLoadDllRvaResolved) {
		static const UNICODE_STRING suffix = RTL_CONSTANT_STRING(L"\\ntdll.dll");
		if (fullImageName->Length >= suffix.Length) {
			UNICODE_STRING tail;
			tail.Buffer = fullImageName->Buffer
				+ (fullImageName->Length - suffix.Length) / sizeof(WCHAR);
			tail.Length = suffix.Length;
			tail.MaximumLength = suffix.Length;
			if (::RtlEqualUnicodeString(&tail, &suffix, TRUE)) {
				ULONG rva = 0;
				if (ResolveLdrLoadDllRva(base, &rva)) {
					g_Data.LdrLoadDllRva = rva;
					g_Data.LdrLoadDllRvaResolved = true;
				}
			}
		}
	}

	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	auto entry = FindLedgerEntryLocked(pid);
	if (entry == nullptr)
		return;
	if (entry->NtdllBase == nullptr) {
		// Every process maps ntdll; record THIS process's base (any ntdll
		// image-load for the pid — there is exactly one per process).
		entry->NtdllBase = base;
	}
	TryInjectLocked(entry, pid);
}

void InjectionOnProcessExit(_In_ ULONG pid) {
	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	auto entry = FindLedgerEntryLocked(pid);
	if (entry != nullptr)
		RemoveLedgerEntryLocked(entry);
}

// Creates + kernel-maps the sensor ring for an entry (challenge time). The
// section is UNNAMED — the only route to it is the duplicate handle the
// challenge hands to the injected sensor.
bool CreateSensorRing(_Inout_ InjectionEntry* entry) {
	if (entry->RingKernelVa)
		return true; // already created (duplicate challenge)
	LARGE_INTEGER maxSize;
	maxSize.QuadPart = SENSOR_RING_SIZE;
	auto status = ::ZwCreateSection(&entry->RingSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
		nullptr, &maxSize, PAGE_READWRITE, SEC_COMMIT, nullptr);
	if (!NT_SUCCESS(status))
		return false;
	SIZE_T viewSize = SENSOR_RING_SIZE;
	status = ::MmMapViewInSystemSpace(entry->RingSection, &entry->RingKernelVa, &viewSize);
	if (!NT_SUCCESS(status)) {
		::ZwClose(entry->RingSection);
		entry->RingSection = nullptr;
		return false;
	}
	::RtlZeroMemory(entry->RingKernelVa, SENSOR_RING_SIZE);
	auto control = (SensorRingControl*)entry->RingKernelVa;
	control->SlotSize = SENSOR_SLOT_SIZE;
	control->SlotCount = SENSOR_SLOT_COUNT;
	entry->RingDrainIndex = 0;
	return true;
}

bool InjectionSensorChallenge(_In_ ULONG pid, _In_ HANDLE callerProcess,
	_Inout_ SensorChallenge* challenge) {
	challenge->Nonce = 0;
	challenge->RingHandle = nullptr;
	challenge->RingSize = 0;
	challenge->SlotSize = 0;
	challenge->SlotCount = 0;

	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	auto entry = FindLedgerEntryLocked(pid);
	if (entry == nullptr || entry->State != InjectionState::Injected) {
		InterlockedIncrement64(&g_Data.SensorsRejected);
		return false;
	}
	if (!CreateSensorRing(entry)) {
		InterlockedIncrement64(&g_Data.AllocFailures);
		return false;
	}

	// Duplicate the section into the caller (the injected sensor process).
	HANDLE caller = nullptr;
	auto status = ::ObOpenObjectByPointer(callerProcess, 0, nullptr,
		PROCESS_DUP_HANDLE, *PsProcessType, UserMode, &caller);
	if (!NT_SUCCESS(status)) {
		InterlockedIncrement64(&g_Data.SensorsRejected);
		return false;
	}
	HANDLE userHandle = nullptr;
	status = ::ZwDuplicateObject(NtCurrentProcess(), entry->RingSection, caller,
		&userHandle, 0, 0, DUPLICATE_SAME_ACCESS);
	::ZwClose(caller);
	if (!NT_SUCCESS(status)) {
		InterlockedIncrement64(&g_Data.SensorsRejected);
		return false;
	}

	challenge->Nonce = entry->Nonce;
	challenge->RingHandle = userHandle;
	challenge->RingSize = SENSOR_RING_SIZE;
	challenge->SlotSize = SENSOR_SLOT_SIZE;
	challenge->SlotCount = SENSOR_SLOT_COUNT;
	return true;
}

bool InjectionSensorRegister(_In_ ULONG pid, _In_ ULONG64 nonce, _In_ ULONG sensorVersion) {
	AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
	auto entry = FindLedgerEntryLocked(pid);
	if (entry == nullptr || entry->State != InjectionState::Injected
		|| entry->Nonce != nonce) {
		InterlockedIncrement64(&g_Data.SensorsRejected);
		return false;
	}
	entry->State = InjectionState::Registered;
	entry->SensorVersion = sensorVersion;
	// Lazy activation: the ring's control block flips to active, and the
	// sensor's hooks start emitting on their next emit call.
	if (entry->RingKernelVa)
		InterlockedExchange(&reinterpret_cast<SensorRingControl*>(entry->RingKernelVa)->State, 1);
	InterlockedIncrement64(&g_Data.SensorsRegistered);
	return true;
}

void InjectionDrainRings() {
	// Snapshot the registered rings under the lock, then drain lock-free:
	// slot sequences make torn/garbage reads detectable, and a hostile host
	// can only damage its own ring (skipped + counted, never the kernel).
	struct RingRef {
		PVOID Va;
		ULONG64 Cursor;
		ULONG Pid;
		ULONG64 CreateTime;
	};
	RingRef rings[64];
	ULONG count = 0;
	{
		AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
		for (auto link = g_Data.InjectionLedger.Flink;
			link != &g_Data.InjectionLedger && count < 64; link = link->Flink) {
			auto entry = CONTAINING_RECORD(link, InjectionEntry, Link);
			if (entry->State == InjectionState::Registered && entry->RingKernelVa != nullptr) {
				rings[count] = { entry->RingKernelVa, entry->RingDrainIndex,
					entry->Pid, entry->CreateTime };
				++count;
			}
		}
	}

	ULONG64 drainedTotal = 0, droppedTotal = 0;
	for (ULONG r = 0; r < count; ++r) {
		auto control = (SensorRingControl*)rings[r].Va;
		if (control->State != 1)
			continue;
		auto drained = rings[r].Cursor;
		auto writeIndex = control->WriteIndex;

		// Overflow resync: once the producer is a full ring ahead, the skipped
		// slots are gone (overwritten) — jump to the newest and count them.
		if (static_cast<LONG64>(writeIndex) - static_cast<LONG64>(drained)
			> static_cast<LONG64>(control->SlotCount)) {
			droppedTotal += writeIndex - static_cast<LONG64>(control->SlotCount) - drained;
			drained = writeIndex - static_cast<LONG64>(control->SlotCount);
		}

		auto slots = reinterpret_cast<PUCHAR>(rings[r].Va) + sizeof(SensorRingControl);
		ULONG drainedNow = 0;
		while (drainedNow < 256 && static_cast<LONG64>(drained) < static_cast<LONG64>(writeIndex)) {
			auto slot = slots + static_cast<ULONGLONG>(drained % static_cast<LONG64>(control->SlotCount))
				* (8 + control->SlotSize);
			auto committed = InterlockedCompareExchange64(
				reinterpret_cast<volatile LONG64*>(slot), 0, 0);
			if (committed != static_cast<LONG64>(drained + 1))
				break; // not committed yet (or torn/garbage — stop, retry later)
			auto payload = slot + 8;
			InjectionEmitBehaviorCall(rings[r].Pid, rings[r].CreateTime,
				*reinterpret_cast<ULONG*>(payload),
				*reinterpret_cast<ULONG*>(payload + 4),
				*reinterpret_cast<ULONG64*>(payload + 8),
				*reinterpret_cast<ULONG64*>(payload + 16),
				*reinterpret_cast<ULONG64*>(payload + 24),
				*reinterpret_cast<ULONG64*>(payload + 32));
			++drained;
			++drainedNow;
			++drainedTotal;
		}

		// Cursor write-back under the lock, matched by ring VA (the entry may
		// have been removed if the process exited mid-drain — acceptable: the
		// ring died with it).
		AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
		for (auto link = g_Data.InjectionLedger.Flink;
			link != &g_Data.InjectionLedger; link = link->Flink) {
			auto entry = CONTAINING_RECORD(link, InjectionEntry, Link);
			if (entry->RingKernelVa == rings[r].Va) {
				entry->RingDrainIndex = drained;
				break;
			}
		}
	}

	if (drainedTotal > 0)
		InterlockedExchange64(&g_Data.SensorEventsDrained,
			g_Data.SensorEventsDrained + drainedTotal);
	if (droppedTotal > 0)
		InterlockedExchange64(&g_Data.SensorEventsDropped,
			g_Data.SensorEventsDropped + droppedTotal);
}
