// D4 self-protection implementation. See Protection.h for the design.
//
// Threat framing: the malware is the adversary. A handle to one of our
// processes with terminate/VM-write rights is a kill-or-tamper primitive;
// stripping is standard EDR self-protection (ObCallbacks). Strips are rare
// by nature, so each one is ALSO an attribution wire record naming the
// opener.

#include "pch.h"
#include "Protection.h"
#include "secoutfall.h"
#include "secoutfallCommon.h"
#include "Memory.h"

namespace {

// Process/thread access rights (Win32 values; kernel headers don't carry
// the named constants).
// Access bits considered dangerous (Win32 values; kernel headers carry the
// THREAD_* names as macros, hence the local k-prefixes).
constexpr ULONG64 kProcessTerminate = 0x0001;
constexpr ULONG64 kProcessCreateThread = 0x0002;
constexpr ULONG64 kProcessVmOperation = 0x0008;
constexpr ULONG64 kProcessVmRead = 0x0010;
constexpr ULONG64 kProcessVmWrite = 0x0020;
constexpr ULONG64 kProcessDupHandle = 0x0040;
constexpr ULONG64 kThreadTerminate = 0x0001;
constexpr ULONG64 kThreadSuspendResume = 0x0002;
constexpr ULONG64 kThreadSetContext = 0x0010;
constexpr ULONG64 kThreadSetThreadAllowed = 0x0080;

// Access bits considered dangerous on a protected PROCESS.
const ULONG64 ProcessStripMask = kProcessTerminate | kProcessCreateThread
	| kProcessVmOperation | kProcessVmRead | kProcessVmWrite | kProcessDupHandle;
// ...and on a protected THREAD.
const ULONG64 ThreadStripMask = kThreadTerminate | kThreadSuspendResume
	| kThreadSetContext | kThreadSetThreadAllowed;

// Protected process names (suffix match, case-insensitive). Empty list =
// nothing protected — protection is opt-in, never blanket.
class ProtectedNames {
public:
	static const ULONG MaxNames = 64;
	static const ULONG MaxBlobBytes = 4096;

	void Init() {
		_names = nullptr;
		_count = 0;
		_blob = nullptr;
	}

	// Same swap-atomically ownership model as FileWatch::Apply.
	bool Apply(_In_opt_ PUNICODE_STRING* names, _In_ ULONG count, _In_opt_ PWCHAR blob) {
		AutoLock<FastMutex> locker(_lock);
		FreeLocked();
		_names = names;
		_count = count;
		_blob = blob;
		return true;
	}

	// Suffix match under the lock. Empty list = NOTHING matches (protection
	// is opt-in — unlike the file-watch lists).
	bool Matches(_In_ PCUNICODE_STRING name) {
		AutoLock<FastMutex> locker(_lock);
		if (_count == 0)
			return false;
		for (ULONG i = 0; i < _count; ++i) {
			auto entry = _names[i];
			if (name->Length < entry->Length)
				continue;
			UNICODE_STRING tail;
			tail.Buffer = name->Buffer + (name->Length - entry->Length) / sizeof(WCHAR);
			tail.Length = entry->Length;
			tail.MaximumLength = entry->Length;
			if (::RtlEqualUnicodeString(&tail, entry, TRUE))
				return true;
		}
		return false;
	}

private:
	void FreeLocked() {
		if (_names) {
			for (ULONG i = 0; i < _count; ++i) {
				if (_names[i])
					ExFreePool(_names[i]);
			}
			ExFreePool(_names);
			_names = nullptr;
		}
		if (_blob) {
			ExFreePool(_blob);
			_blob = nullptr;
		}
		_count = 0;
	}

	FastMutex _lock;
	PUNICODE_STRING* _names;
	ULONG _count;
	PWCHAR _blob;
};

// Protected pid table: pid -> creation time. Small, fixed cap (our own
// process set is a handful; 128 is generous).
class ProtectedTable {
public:
	static const ULONG MaxEntries = 128;

	void Init() {
		InitializeListHead(&_head);
		_count = 0;
	}

	// Returns false when full.
	bool Add(_In_ ULONG pid, _In_ ULONG64 createTime) {
		AutoLock<FastMutex> locker(_lock);
		if (FindLocked(pid) || _count >= MaxEntries)
			return false;
		auto entry = (Entry*)::ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Entry), DRIVER_TAG);
		if (entry == nullptr)
			return false;
		entry->Pid = pid;
		entry->CreateTime = createTime;
		InsertTailList(&_head, &entry->Link);
		_count++;
		return true;
	}

	void Remove(_In_ ULONG pid) {
		AutoLock<FastMutex> locker(_lock);
		if (auto entry = FindLocked(pid)) {
			RemoveEntryList(&entry->Link);
			ExFreePool(entry);
			_count--;
		}
	}

	// Teardown for ProtectionCleanup. Pool-tag memory is NOT reclaimed at
	// driver unload (the old comment claimed otherwise) — without this walk,
	// entries for still-running protected processes leaked nonpaged pool
	// until reboot. Undo registration happens in the caller, so no callback
	// can race this.
	void Clear() {
		AutoLock<FastMutex> locker(_lock);
		while (!IsListEmpty(&_head)) {
			auto link = RemoveHeadList(&_head);
			ExFreePool(CONTAINING_RECORD(link, Entry, Link));
		}
		_count = 0;
	}

	bool Contains(_In_ ULONG pid) {
		AutoLock<FastMutex> locker(_lock);
		return FindLocked(pid) != nullptr;
	}

	// Identity lookup for the attribution record; 0 when unknown.
	ULONG64 CreateTimeOf(_In_ ULONG pid) {
		AutoLock<FastMutex> locker(_lock);
		auto entry = FindLocked(pid);
		return entry ? entry->CreateTime : 0;
	}

	ULONG Count() const { return _count; }

private:
	struct Entry {
		LIST_ENTRY Link;
		ULONG Pid;
		ULONG64 CreateTime;
	};

	Entry* FindLocked(_In_ ULONG pid) {
		for (auto link = _head.Flink; link != &_head; link = link->Flink) {
			auto entry = CONTAINING_RECORD(link, Entry, Link);
			if (entry->Pid == pid)
				return entry;
		}
		return nullptr;
	}

	LIST_ENTRY _head;
	FastMutex _lock;
	ULONG _count;
};

ProtectedNames* g_Names;
ProtectedTable* g_Table;

OB_PREOP_CALLBACK_STATUS ObPreOperation(_In_ PVOID registrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION information) {
	UNREFERENCED_PARAMETER(registrationContext);

	auto isProcess = information->ObjectType == *PsProcessType;
	auto isThread = information->ObjectType == *PsThreadType;
	if (!isProcess && !isThread)
		return OB_PREOP_SUCCESS;

	// The protected table holds PROCESS pids. A thread handle must resolve
	// to its OWNING process for the lookup — the review found the raw TID
	// compared against the pid table, so thread protection never fired.
	auto targetPid = isProcess
		? HandleToULong(PsGetProcessId(static_cast<PEPROCESS>(information->Object)))
		: HandleToULong(PsGetThreadProcessId(static_cast<PETHREAD>(information->Object)));
	if (!g_Table->Contains(targetPid))
		return OB_PREOP_SUCCESS; // not ours

	// Trusted callers: the System process and our own protected processes
	// (the agent must be able to manage the user-actor it launched).
	auto caller = HandleToULong(PsGetCurrentProcessId());
	if (caller == 4 || g_Table->Contains(caller))
		return OB_PREOP_SUCCESS;

	ULONG64 mask = isProcess ? ProcessStripMask : ThreadStripMask;
	ULONG64 original = 0;
	ULONG64 stripped = 0;

	if (FlagOn(information->Flags, OB_OPERATION_HANDLE_CREATE)) {
		original = information->Parameters->CreateHandleInformation.DesiredAccess;
		stripped = original & mask;
		if (stripped != 0) {
			information->Parameters->CreateHandleInformation.DesiredAccess =
				static_cast<ACCESS_MASK>(original & ~mask);
		}
	}
	if (stripped == 0 && FlagOn(information->Flags, OB_OPERATION_HANDLE_DUPLICATE)) {
		original = information->Parameters->DuplicateHandleInformation.DesiredAccess;
		stripped = original & mask;
		if (stripped != 0) {
			information->Parameters->DuplicateHandleInformation.DesiredAccess =
				static_cast<ACCESS_MASK>(original & ~mask);
		}
	}

	if (stripped == 0)
		return OB_PREOP_SUCCESS;

	InterlockedIncrement64(&g_Data.ProtectionsStripped);

	// Attribution record: opener pid/identity in the header, target + what
	// was removed in the payload. Record allocation is PagedPool — emit only
	// at PASSIVE (rare DISPATCH strips are counted, never allocated).
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return OB_PREOP_SUCCESS;
	auto createTime = g_Table->CreateTimeOf(targetPid);
	ProtectionEmitStrippedEvent(caller, g_Data.Identities->Lookup(caller),
		targetPid, createTime, isThread ? 1 : 0, original, stripped);
	return OB_PREOP_SUCCESS;
}

const UNICODE_STRING ObAltitudeForCallback() {
	// Function-local static: the string literal has static storage, and the
	// initializer is constant-folded — no .CRT entry.
	static UNICODE_STRING altitude;
	static bool initialized = false;
	if (!initialized) {
		RtlInitUnicodeString(&altitude, L"389912.05");
		initialized = true;
	}
	return altitude;
}

} // namespace

void ProtectionInit() {
	g_Names = new (NonPagedPool) ProtectedNames;
	g_Names->Init();
	g_Table = new (NonPagedPool) ProtectedTable;
	g_Table->Init();
}

void ProtectionCleanup() {
	// Policy/table entries live in nonpaged pool and are freed here; the Ob
	// registration itself was already undone by the caller.
	if (g_Names) {
		g_Names->Apply(nullptr, 0, nullptr);
		delete g_Names;
		g_Names = nullptr;
	}
	if (g_Table) {
		g_Table->Clear();
		delete g_Table;
		g_Table = nullptr;
	}
}

NTSTATUS ProtectionRegisterCallbacks(_In_ PDRIVER_OBJECT) {

	OB_OPERATION_REGISTRATION operations[] = {
		{ PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			ObPreOperation, nullptr },
		{ PsThreadType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			ObPreOperation, nullptr },
		{ nullptr, 0, nullptr, nullptr }
	};

	OB_CALLBACK_REGISTRATION registration = {};
	registration.Version = OB_FLT_REGISTRATION_VERSION;
	registration.OperationRegistrationCount = 2;
	registration.Altitude = ObAltitudeForCallback();
	registration.RegistrationContext = nullptr;
	registration.OperationRegistration = operations;

	return ::ObRegisterCallbacks(&registration, &g_Data.ObRegistration);
}

void ProtectionUnregisterCallbacks() {
	if (g_Data.ObRegistration) {
		::ObUnRegisterCallbacks(g_Data.ObRegistration);
		g_Data.ObRegistration = nullptr;
	}
}

bool ProtectionSetPolicy(_In_ bool enabled, _In_ PCUNICODE_STRING names) {
	if (!enabled) {
		g_Names->Apply(nullptr, 0, nullptr);
		return true;
	}

	// Parse the NUL-terminated name blob into fresh arrays (Apply swaps
	// atomically; allocation failure keeps the old list).
	ULONG count = 0;
	ULONG offset = 0;
	while (offset + sizeof(WCHAR) <= names->Length) {
		ULONG len = 0;
		auto cursor = names->Buffer + offset / sizeof(WCHAR);
		while (offset + (len + 1) * sizeof(WCHAR) <= names->Length && cursor[len] != L'\0')
			++len;
		if (len == 0)
			break;
		++count;
		offset += (len + 1) * sizeof(WCHAR);
	}
	if (count == 0 || count > ProtectedNames::MaxNames
		|| names->Length > ProtectedNames::MaxBlobBytes) {
		return false;
	}

	auto blob = (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED, names->Length, DRIVER_TAG);
	auto exts = (PUNICODE_STRING*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
		sizeof(PUNICODE_STRING) * count, DRIVER_TAG);
	if (blob == nullptr || exts == nullptr) {
		if (blob) ExFreePool(blob);
		if (exts) ExFreePool(exts);
		return false;
	}
	::memcpy(blob, names->Buffer, names->Length);

	ULONG index = 0;
	offset = 0;
	while (offset + sizeof(WCHAR) <= names->Length && index < count) {
		ULONG len = 0;
		auto cursor = names->Buffer + offset / sizeof(WCHAR);
		while (offset + (len + 1) * sizeof(WCHAR) <= names->Length && cursor[len] != L'\0')
			++len;
		if (len == 0)
			break;
		auto entry = (PUNICODE_STRING)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
			sizeof(UNICODE_STRING), DRIVER_TAG);
		if (entry == nullptr)
			break;
		entry->Buffer = blob + offset / sizeof(WCHAR);
		entry->Length = static_cast<USHORT>(len * sizeof(WCHAR));
		entry->MaximumLength = entry->Length;
		exts[index] = entry;
		++index;
		offset += (len + 1) * sizeof(WCHAR);
	}
	if (index != count) {
		for (ULONG i = 0; i < index; ++i)
			ExFreePool(exts[i]);
		ExFreePool(exts);
		ExFreePool(blob);
		return false;
	}
	g_Names->Apply(exts, count, blob);
	return true;
}

void ProtectionOnProcessCreate(_In_ ULONG pid, _In_ ULONG64 createTime,
	_In_opt_ PCUNICODE_STRING imageFileName) {
	if (imageFileName == nullptr)
		return;
	if (g_Names->Matches(imageFileName))
		g_Table->Add(pid, createTime);
}

void ProtectionOnProcessExit(_In_ ULONG pid) {
	g_Table->Remove(pid);
}

NTSTATUS ProtectionSetDeviceSecurity(_In_ PDEVICE_OBJECT device,
	_In_ PUCHAR sdBytes, _In_ ULONG sdLength) {
	// The blob is a self-relative SECURITY_DESCRIPTOR built user-side
	// (SDDL conversion is a user-mode facility). Apply it to the device's
	// DACL via a temporary kernel handle.
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
	HANDLE deviceHandle = nullptr;
	auto status = ::ObOpenObjectByPointer(device, OBJ_KERNEL_HANDLE, nullptr,
		WRITE_DAC, nullptr, KernelMode, &deviceHandle);
	if (!NT_SUCCESS(status))
		return status;

	auto sd = (PSECURITY_DESCRIPTOR)::ExAllocatePool2(POOL_FLAG_PAGED, sdLength, DRIVER_TAG);
	if (sd == nullptr) {
		::ZwClose(deviceHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	::memcpy(sd, sdBytes, sdLength);

	// Caller-built SD: validate before applying (hostile input doctrine).
	status = ::RtlValidRelativeSecurityDescriptor(sd, sdLength,
		DACL_SECURITY_INFORMATION);
	if (NT_SUCCESS(status)) {
		status = ::ZwSetSecurityObject(deviceHandle, DACL_SECURITY_INFORMATION, sd);
	} else {
		status = STATUS_INVALID_PARAMETER;
	}
	ExFreePool(sd);
	::ZwClose(deviceHandle);
	return status;
}
