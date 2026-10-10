// secoutfall — process/thread/image/registry telemetry driver (WDM), adapted
// from the WKP SysMon base (Pavel Yosifovich, Windows Kernel Programming).
//
// D1 state: wire format v2 (magic + version + u32 sizes + truncation flags +
// per-boot sequence + pid/creation-time identity), image-load telemetry,
// registry create/delete/set-value, loss counters surfaced via GET_STATS,
// skip+count oversized-item drain policy. The full hardening list and phase
// plan live in KERNEL.md at the repo root.
//
// Security posture: the device is SDDL-restricted (SYSTEM + Administrators),
// every IOCTL buffer is validated, and every string captured from callbacks
// is length-clamped with truncation flagged on the wire. The malware is a
// user of this device.

#include "pch.h"
#include "secoutfallCommon.h"
#include "Injection.h"
#include "Protection.h"
#include "secoutfall.h"
#include "Memory.h"

DRIVER_UNLOAD SecOutfallUnload;
DRIVER_DISPATCH SecOutfallCreateClose;
DRIVER_DISPATCH SecOutfallDeviceControl;

void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
void OnImageLoadNotify(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS OnRegistryNotify(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2);

// Minifilter (D2, same .sys as the control device): file telemetry through
// the flood-class queue, single drain path with the control queue.
FLT_PREOP_CALLBACK_STATUS FLTAPI SecOutfallPreSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PVOID* NewCompletionContext);
FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostWrite(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostCleanup(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// Lab altitude: FSFilter activity-monitor range. A real altitude assignment
// matters only when leaving the lab (KERNEL.md open items).
#define SECOUTFALL_FILTER_ALTITUDE L"389910.02"
#define SECOUTFALL_INSTANCE_NAME L"SecOutfall Instance"

Globals g_Data;

// Device setup class GUID for the secure device creation (unique per driver).
const GUID GUID_DEVICECLASS_SECOUTFALL = {
	0xb7a9e2d1, 0x4c3f, 0x4e8b, { 0x9a, 0x6d, 0x15, 0xf2, 0xc8, 0xe7, 0xb4, 0xa0 }
};

namespace {

// Minifilter registration: post-op telemetry only, observe-only. Rename old
// paths need a PRE hook (post-rename name queries return the NEW name).
const FLT_OPERATION_REGISTRATION FileCallbacks[] = {
	{ IRP_MJ_CREATE, 0, nullptr, SecOutfallPostCreate },
	{ IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, nullptr, SecOutfallPostWrite },
	{ IRP_MJ_CLEANUP, 0, nullptr, SecOutfallPostCleanup },
	{ IRP_MJ_SET_INFORMATION, 0, SecOutfallPreSetInfo, SecOutfallPostSetInfo },
	{ IRP_MJ_OPERATION_END }
};

// Per-stream drop state: CopyPending = armed at first write, link failed (or
// not attempted yet) → cleanup copies final content; Linked = tombstone in
// place; CopyDone/CopyFailed = cleanup ran.
struct DropStreamContext {
	volatile LONG State;
	UNICODE_STRING StoredName;        // points into Buffer
	WCHAR Buffer[64];                 // "drop-<8 hex><ext>" — bounded
};

constexpr LONG DROP_COPY_PENDING = 0;
constexpr LONG DROP_LINKED = 1;
constexpr LONG DROP_COPY_DONE = 2;
constexpr LONG DROP_COPY_FAILED = 3;

// "drop-<8 hex><ext>" — no CRT: hex loop, wide chars directly. The extension
// (with the dot) is the path's last-dot suffix, capped by the buffer bound.
void GenerateStoredName(_Out_ DropStreamContext* context, _In_ PCUNICODE_STRING path) {
	auto counter = InterlockedIncrement64(&g_Data.DropCounter) & 0xFFFFFFFF;
	USHORT i = 0;
	for (auto c : L"drop-") {
		if (c != L'\0' && i < 64)
			context->Buffer[i++] = c;
	}
	const WCHAR hex[] = L"0123456789abcdef";
	for (int shift = 28; shift >= 0; shift -= 4) {
		if (i < 64)
			context->Buffer[i++] = hex[(counter >> shift) & 0xF];
	}
	LONG dot = -1;
	auto pathWchars = static_cast<LONG>(path->Length / sizeof(WCHAR));
	for (LONG k = pathWchars - 1; k >= 0; --k) {
		if (path->Buffer[k] == L'.') {
			dot = k;
			break;
		}
	}
	if (dot >= 0) {
		for (LONG k = dot; k < pathWchars && i < 64; ++k)
			context->Buffer[i++] = path->Buffer[k];
	}
	context->StoredName.Buffer = context->Buffer;
	context->StoredName.Length = static_cast<USHORT>(i * sizeof(WCHAR));
	context->StoredName.MaximumLength = context->StoredName.Length;
}

const FLT_CONTEXT_REGISTRATION DropContextRegistration[] = {
	// Per-stream drop state: first matching write tombstones the file, later
	// writes and the cleanup check the same context.
	{ FLT_STREAM_CONTEXT, 0, nullptr, sizeof(DropStreamContext), DRIVER_TAG },
	{ FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),   // Size
	FLT_REGISTRATION_VERSION,   // Version
	0,                          // Flags
	DropContextRegistration,
	FileCallbacks,
	nullptr,                    // FilterUnload: DriverUnload calls FltUnregisterFilter
	nullptr,                    // InstanceSetup (attachment via registry instance key)
	nullptr,                    // InstanceQueryTeardown
	nullptr,                    // InstanceTeardownStart
	nullptr,                    // InstanceTeardownComplete
	nullptr,                    // GenerateFileName
	nullptr,                    // GenerateDestinationFileName
	nullptr,                    // NormalizeNameComponent
	nullptr,                    // NormalizeNameComponentEx
	nullptr,                    // SectionNotification
};

// Copies up to `capBytes` (whole WCHARs) from a counted string. Returns the
// bytes copied; `truncated` reports that the source did not fit — surfaced
// on the wire as a truncation flag, because a flagged string is a PREFIX of
// the truth, never a different string.
USHORT CopyNameW(_Out_ WCHAR* dest, _In_ PCUNICODE_STRING src, _In_ USHORT capBytes, _Out_ bool& truncated) {
	truncated = false;
	USHORT bytes = 0;
	if (src && src->Buffer && src->Length > 0) {
		bytes = static_cast<USHORT>(min(src->Length, capBytes));
		bytes &= static_cast<USHORT>(~1); // whole WCHARs only
		::memcpy(dest, src->Buffer, bytes);
		truncated = bytes < src->Length;
	}
	return bytes;
}

ULONG64 NextIdentityMiss() {
	return InterlockedIncrement64(&g_Data.IdentityMisses);
}

// Allocates a queue item and fills the v2 record header. Returns the WIRE
// record (the ItemFull wrapper header is invisible on the wire). `totalSize`
// is the full wire record size, header included.
RecordHeader* AllocRecord(_In_ ULONG totalSize, _In_ RecordType type, _In_ ULONG pid, _In_opt_ ULONG64 processCreateTime) {
	auto item = (ItemFull<RecordHeader>*)::ExAllocatePool2(POOL_FLAG_PAGED,
		sizeof(ItemFull<RecordHeader>) + totalSize, DRIVER_TAG);
	if (item == nullptr) {
		InterlockedIncrement64(&g_Data.AllocFailures);
		return nullptr;
	}

	auto header = &item->Item;
	header->Magic = SECOUTFALL_WIRE_MAGIC;
	header->Version = SECOUTFALL_WIRE_VERSION;
	header->TruncFlags = TRUNC_NONE;
	header->Type = static_cast<USHORT>(type);
	header->HeaderSize = sizeof(RecordHeader);
	header->ProcessId = pid;
	header->Sequence = InterlockedIncrement64(&g_Data.NextSequence);
	::KeQuerySystemTimePrecise(reinterpret_cast<PLARGE_INTEGER>(&header->Time));
	header->ProcessCreateTime = processCreateTime;
	header->Size = totalSize;
	return header;
}

void PushRecord(_Inout_ ItemFull<RecordHeader>* item, _In_ bool fileClass = false) {
	(fileClass ? g_Data.Files : g_Data.Items)->Push(item);
}

// Pushes a drops-class record: stop-collect on overflow — existing evidence
// is never evicted, refusal is counted.
void PushDropRecord(_Inout_ ItemFull<RecordHeader>* item) {
	if (!g_Data.Drops->TryPush(item))
		InterlockedIncrement64(&g_Data.DropsStopped);
}

// Ring-drain promotion (Injection.cpp): a validated sensor slot becomes a
// BehaviorCall wire record in the flood-class queue. pid/identity/time come
// from the kernel's authoritative values, never from the ring.
void EmitBehaviorCallInternal(_In_ ULONG pid, _In_ ULONG64 createTime, _In_ ULONG threadId,
	_In_ ULONG api, _In_ ULONG64 arg0, _In_ ULONG64 arg1, _In_ ULONG64 arg2, _In_ ULONG64 arg3) {
	auto header = AllocRecord(BehaviorCallFixed, BehaviorCall, pid, createTime);
	if (header == nullptr)
		return;
	auto record = reinterpret_cast<BehaviorCallRecord*>(header);
	record->ThreadId = threadId;
	record->Api = api;
	record->Arg0 = arg0;
	record->Arg1 = arg1;
	record->Arg2 = arg2;
	record->Arg3 = arg3;
	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
}

// Drop-capture target directory, copied out under the lock.
USHORT DropsDir(_Out_ WCHAR* out, _In_ USHORT capBytes) {
	return g_Data.Target->Get(out, capBytes);
}

// Creates a hard link `storedName` inside the drops directory pointing at
// `sourcePath` (FileLinkInformation on a directory handle). Same-volume
// only — cross-volume returns failure and the cleanup copies instead.
bool CreateHardLinkInDrops(_In_ PFLT_INSTANCE instance, _In_ PCUNICODE_STRING sourcePath,
	_In_ PCUNICODE_STRING storedName) {
// FileLinkInformation semantics: open the EXISTING (source) file, then pass
// the NEW link's full path (drops dir + stored name) in FileName.
	WCHAR dirBuf[MaxFilePathBytes / sizeof(WCHAR)];
	auto dirBytes = DropsDir(dirBuf, sizeof(dirBuf));
	if (dirBytes == 0)
		return false;
	USHORT dirWchars = dirBytes / sizeof(WCHAR);
	if (dirWchars + 1 + storedName->Length / sizeof(WCHAR) > MaxFilePathBytes / sizeof(WCHAR))
		return false;

	WCHAR destBuf[MaxFilePathBytes / sizeof(WCHAR)];
	::memcpy(destBuf, dirBuf, dirBytes);
	destBuf[dirWchars] = L'\\';
	::memcpy(destBuf + dirWchars + 1, storedName->Buffer, storedName->Length);
	UNICODE_STRING dest;
	dest.Buffer = destBuf;
	dest.Length = static_cast<USHORT>((dirWchars + 1 + storedName->Length / sizeof(WCHAR)) * sizeof(WCHAR));
	dest.MaximumLength = dest.Length;

	OBJECT_ATTRIBUTES srcOa;
	InitializeObjectAttributes(&srcOa, const_cast<PUNICODE_STRING>(sourcePath),
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	HANDLE srcHandle = nullptr;
	IO_STATUS_BLOCK iosb = {};
	auto status = ::FltCreateFileEx2(g_Data.Filter, instance, &srcHandle, nullptr,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE, &srcOa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0, 0, nullptr);
	if (!NT_SUCCESS(status))
		return false;

	auto bufferSize = sizeof(FILE_LINK_INFORMATION) + dest.Length;
	auto link = (FILE_LINK_INFORMATION*)::ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, DRIVER_TAG);
	if (link == nullptr) {
		::ZwClose(srcHandle);
		InterlockedIncrement64(&g_Data.AllocFailures);
		return false;
	}
	link->ReplaceIfExists = FALSE;
	link->FileNameLength = dest.Length;
	::memcpy(link->FileName, dest.Buffer, dest.Length);
	status = ::ZwSetInformationFile(srcHandle, &iosb, link, static_cast<ULONG>(bufferSize), FileLinkInformation);
	ExFreePool(link);
	::ZwClose(srcHandle);
	return NT_SUCCESS(status);
}

// Full-content stream copy into the drops directory (cleanup-time fallback:
// final content, cross-volume safe). 64 KiB chunks, opened through our own
// instance so the copies never call back into this filter.
bool CopyFileToDrops(_In_ PFLT_INSTANCE instance, _In_ PCUNICODE_STRING sourcePath,
	_In_ PCUNICODE_STRING storedName) {
	WCHAR dirBuf[MaxFilePathBytes / sizeof(WCHAR)];
	auto dirBytes = DropsDir(dirBuf, sizeof(dirBuf));
	if (dirBytes == 0)
		return false;

	// destination full path: dir + L'\' + storedName
	WCHAR destBuf[MaxFilePathBytes / sizeof(WCHAR)];
	USHORT destWchars = dirBytes / sizeof(WCHAR);
	if (destWchars + 1 + storedName->Length / sizeof(WCHAR) > MaxFilePathBytes / sizeof(WCHAR))
		return false;
	::memcpy(destBuf, dirBuf, dirBytes);
	destBuf[destWchars] = L'\\';
	::memcpy(destBuf + destWchars + 1, storedName->Buffer, storedName->Length);
	destWchars += 1 + storedName->Length / sizeof(WCHAR);
	UNICODE_STRING dest;
	dest.Buffer = destBuf;
	dest.Length = static_cast<USHORT>(destWchars * sizeof(WCHAR));
	dest.MaximumLength = dest.Length;

	OBJECT_ATTRIBUTES srcOa;
	InitializeObjectAttributes(&srcOa, const_cast<PUNICODE_STRING>(sourcePath),
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	HANDLE srcHandle = nullptr;
	PFILE_OBJECT srcObject = nullptr;
	IO_STATUS_BLOCK iosb = {};
	auto status = ::FltCreateFileEx2(g_Data.Filter, instance, &srcHandle, &srcObject,
		FILE_GENERIC_READ, &srcOa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0, 0, nullptr);
	if (!NT_SUCCESS(status))
		return false;

	OBJECT_ATTRIBUTES dstOa;
	InitializeObjectAttributes(&dstOa, &dest, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	HANDLE dstHandle = nullptr;
	status = ::FltCreateFileEx2(g_Data.Filter, instance, &dstHandle, nullptr,
		FILE_GENERIC_WRITE, &dstOa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		nullptr, 0, 0, nullptr);
	if (!NT_SUCCESS(status)) {
		::FltClose(srcHandle);
		if (srcObject)
			::FltObjectDereference(srcObject);
		return false;
	}

	auto chunk = (PUCHAR)::ExAllocatePool2(POOL_FLAG_PAGED, 65536, DRIVER_TAG);
	auto ok = chunk != nullptr;
	LARGE_INTEGER offset {};
	while (ok) {
		ULONG bytesRead = 0;
		auto readStatus = ::FltReadFile(instance, srcObject, &offset, 65536, chunk, 0,
			&bytesRead, nullptr, nullptr);
		if (readStatus == STATUS_END_OF_FILE)
			break;
		if (!NT_SUCCESS(readStatus)) {
			ok = false;
			break;
		}
		if (bytesRead == 0)
			break;
		auto writeStatus = ::ZwWriteFile(dstHandle, nullptr, nullptr, nullptr, &iosb,
			chunk, bytesRead, &offset, nullptr);
		if (!NT_SUCCESS(writeStatus)) {
			ok = false;
			break;
		}
		offset.QuadPart += bytesRead;
	}
	if (chunk)
		ExFreePool(chunk);
	::ZwClose(dstHandle);
	::FltClose(srcHandle);
	if (srcObject)
		::FltObjectDereference(srcObject);
	return ok;
}

// Emits the drop-evidence record (drops-class queue, stop-collect).
void EmitDropCaptured(_In_ PCUNICODE_STRING path, _In_ PCUNICODE_STRING storedName,
	_In_ ULONG method, _In_ ULONG pid) {
	bool pathTruncated = false;
	WCHAR pathScratch[MaxFilePathBytes / sizeof(WCHAR)];
	auto pathBytes = CopyNameW(pathScratch, path, MaxFilePathBytes, pathTruncated);
	bool storedTruncated = false;
	WCHAR storedScratch[64];
	auto storedBytes = CopyNameW(storedScratch, storedName, sizeof(storedScratch), storedTruncated);

	auto header = AllocRecord(DropCapturedFixed + pathBytes + storedBytes, DropCaptured, pid,
		g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;
	if (pathTruncated)
		header->TruncFlags |= TRUNC_FILE_PATH;
	if (storedTruncated)
		header->TruncFlags |= TRUNC_NEW_PATH; // second-path flag reused

	auto record = reinterpret_cast<DropCapturedRecord*>(header);
	record->PathOffset = DropCapturedFixed;
	record->PathBytes = pathBytes;
	record->StoredOffset = static_cast<USHORT>(record->PathOffset + pathBytes);
	record->StoredBytes = storedBytes;
	record->Method = method;
	auto body = reinterpret_cast<UCHAR*>(header);
	::memcpy(body + record->PathOffset, pathScratch, pathBytes);
	::memcpy(body + record->StoredOffset, storedScratch, storedBytes);

	PushDropRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
}

// First matching write: mark the stream (context dedup), generate the stored
// name, try the hard link. CopyPending survives to cleanup on link failure.
void TryCaptureDrop(_In_ PFLT_INSTANCE instance, _In_ PFLT_CALLBACK_DATA data,
	_In_ PCUNICODE_STRING path, _In_ ULONG pid) {
	if (!g_Data.DropWatch->Matches(path))
		return;
	// FltCreateFileEx2 is PASSIVE-max: rare busy completions are counted, the
	// cleanup fallback still covers the stream.
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		InterlockedIncrement64(&g_Data.DropsMissedBusy);
		return;
	}

	DropStreamContext* context = nullptr;
	auto status = ::FltAllocateContext(g_Data.Filter, FLT_STREAM_CONTEXT,
		sizeof(DropStreamContext), NonPagedPool,
		reinterpret_cast<PFLT_CONTEXT*>(&context));
	if (!NT_SUCCESS(status)) {
		InterlockedIncrement64(&g_Data.AllocFailures);
		return;
	}
	context->State = DROP_COPY_PENDING;
	GenerateStoredName(context, path);
	status = ::FltSetStreamContext(instance, data->Iopb->TargetFileObject,
		FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, nullptr);
	if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
		::FltReleaseContext(context);
		return; // another write of the same stream is capturing
	}
	if (!NT_SUCCESS(status)) {
		::FltReleaseContext(context);
		InterlockedIncrement64(&g_Data.AllocFailures);
		return;
	}

	if (CreateHardLinkInDrops(instance, path, &context->StoredName)) {
		InterlockedExchange(&context->State, DROP_LINKED);
		EmitDropCaptured(path, &context->StoredName, DROP_METHOD_HARDLINK, pid);
	} else {
		InterlockedIncrement64(&g_Data.DropsLinkFailed);
		// state stays CopyPending: the cleanup callback copies final content
	}
	::FltReleaseContext(context);
}

// Cleanup-time fallback for streams whose hard link failed: copy final
// content. State transitions make this exactly-once per stream.
void TryCleanupCopy(_In_ PFLT_INSTANCE instance, _In_ PFLT_CALLBACK_DATA data,
	_In_ PCUNICODE_STRING path, _In_ ULONG pid) {
	DropStreamContext* context = nullptr;
	if (!NT_SUCCESS(::FltGetStreamContext(instance, data->Iopb->TargetFileObject,
		reinterpret_cast<PFLT_CONTEXT*>(&context))))
		return; // never a drop candidate
	auto state = InterlockedExchange(&context->State, DROP_COPY_DONE);
	::FltReleaseContext(context);
	if (state != DROP_COPY_PENDING)
		return; // linked at first write, or a duplicate cleanup
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		InterlockedExchange(&context->State, DROP_COPY_PENDING);
		InterlockedIncrement64(&g_Data.DropsMissedBusy);
		return;
	}
	if (CopyFileToDrops(instance, path, &context->StoredName))
		EmitDropCaptured(path, &context->StoredName, DROP_METHOD_COPY, pid);
	else
		InterlockedIncrement64(&g_Data.DropsCopyFailed);
}


// Normalized full path for a file-system callback, or nullptr on failure
// (counted — a skipped record is honest loss, not silence). Above APC_LEVEL
// only the name cache may be queried; post-write from DPC land degrades to
// cache-only and skips on a miss.
PFLT_FILE_NAME_INFORMATION QueryFileName(_In_ PFLT_CALLBACK_DATA data) {
	auto queryFlags = KeGetCurrentIrql() > APC_LEVEL
		? FLT_FILE_NAME_QUERY_CACHE_ONLY
		: FLT_FILE_NAME_QUERY_DEFAULT;
	PFLT_FILE_NAME_INFORMATION name = nullptr;
	if (!NT_SUCCESS(::FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | queryFlags, &name))) {
		InterlockedIncrement64(&g_Data.FileNameQueriesFailed);
		return nullptr;
	}
	return name;
}

// Emits a one-path file record (created / cleaned_up / deleted).
void EmitFileRecord(_In_ RecordType type, _In_ PCUNICODE_STRING path, _In_ ULONG pid) {
	bool truncated = false;
	WCHAR scratch[MaxFilePathBytes / sizeof(WCHAR)];
	auto pathBytes = CopyNameW(scratch, path, MaxFilePathBytes, truncated);

	auto header = AllocRecord(FileFixed + pathBytes, type, pid, g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;
	if (truncated)
		header->TruncFlags |= TRUNC_FILE_PATH;

	auto record = reinterpret_cast<FileRecord*>(header);
	record->PathOffset = FileFixed;
	record->PathBytes = pathBytes;
	::memcpy(reinterpret_cast<UCHAR*>(header) + record->PathOffset, scratch, pathBytes);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
}

// Old path is captured by the PRE callback (post-rename queries return the
// NEW name); a missing context means the rename goes unrecorded — the failed
// query was already counted there.
struct RenameContext {
	UNICODE_STRING OldPath; // Buffer follows the struct, nonpaged
};


void EmitFileRenamed(_In_opt_ const RenameContext* context, _In_ PCUNICODE_STRING newPath, _In_ ULONG pid) {
	bool oldTruncated = false, newTruncated = false;
	WCHAR oldScratch[MaxFilePathBytes / sizeof(WCHAR)];
	WCHAR newScratch[MaxFilePathBytes / sizeof(WCHAR)];
	// USHORT(0), not bare 0: a bare int would promote the ternary (and
	// oldBytes) to int, reintroducing a narrowing warning at every use.
	auto oldBytes = context ? CopyNameW(oldScratch, &context->OldPath, MaxFilePathBytes, oldTruncated)
	                        : static_cast<USHORT>(0);
	auto newBytes = CopyNameW(newScratch, newPath, MaxFilePathBytes, newTruncated);

	auto header = AllocRecord(FileRenamedFixed + oldBytes + newBytes, FileRenamed, pid,
		g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;
	if (oldTruncated)
		header->TruncFlags |= TRUNC_OLD_PATH;
	if (newTruncated)
		header->TruncFlags |= TRUNC_NEW_PATH;

	auto record = reinterpret_cast<FileRenamedRecord*>(header);
	record->OldPathOffset = FileRenamedFixed;
	record->OldPathBytes = oldBytes;
	record->NewPathOffset = static_cast<USHORT>(record->OldPathOffset + oldBytes);
	record->NewPathBytes = newBytes;
	auto body = reinterpret_cast<UCHAR*>(header);
	if (oldBytes > 0)
		::memcpy(body + record->OldPathOffset, oldScratch, oldBytes);
	::memcpy(body + record->NewPathOffset, newScratch, newBytes);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
}

// \REGISTRY\MACHINE prefix match that rejects longer accidental prefixes
// (\REGISTRY\MACHINEXYZ must not match). Registry paths are case-insensitive.
bool IsMachineKey(_In_ PCUNICODE_STRING name) {
	static const UNICODE_STRING machine = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE");
	if (!::RtlPrefixUnicodeString(&machine, name, TRUE))
		return false;
	if (name->Length > machine.Length) {
		auto next = name->Buffer[machine.Length / sizeof(WCHAR)];
		if (next != L'\\')
			return false;
	}
	return true;
}

// Full key path for a registry-callback object. Returns nullptr on failure —
// the caller skips the record rather than emit a nameless one.
PCUNICODE_STRING GetKeyPath(_In_ PVOID Object) {
	PCUNICODE_STRING name = nullptr;
	if (!NT_SUCCESS(::CmCallbackGetKeyObjectIDEx(&g_Data.RegistryCookie, Object, nullptr, &name, 0)))
		return nullptr;
	return name;
}

void EmitRegistryKeyRecord(_In_ RecordType type, _In_ PCUNICODE_STRING path) {
	bool truncated = false;
	WCHAR pathScratch[MaxKeyPathBytes / sizeof(WCHAR)];
	auto pathBytes = CopyNameW(pathScratch, path, MaxKeyPathBytes, truncated);

	auto header = AllocRecord(RegistryKeyFixed + pathBytes, type,
		HandleToULong(PsGetCurrentProcessId()), g_Data.Identities->Lookup(HandleToULong(PsGetCurrentProcessId())));
	if (header == nullptr)
		return;
	if (truncated)
		header->TruncFlags |= TRUNC_KEY_PATH;

	auto record = reinterpret_cast<RegistryKeyRecord*>(header);
	record->PathOffset = RegistryKeyFixed;
	record->PathBytes = pathBytes;
	::memcpy(reinterpret_cast<UCHAR*>(header) + record->PathOffset, pathScratch, pathBytes);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
}

void EmitRegistrySetValue(_In_ PCUNICODE_STRING keyPath, _In_ PCUNICODE_STRING valueName,
	_In_ ULONG dataType, _In_reads_bytes_(dataLength) PVOID data, _In_ ULONG dataLength) {
	bool keyTruncated = false, valueTruncated = false, dataTruncated = false;
	WCHAR keyScratch[MaxKeyPathBytes / sizeof(WCHAR)];
	WCHAR valueScratch[MaxValueNameBytes / sizeof(WCHAR)];
	auto keyBytes = CopyNameW(keyScratch, keyPath, MaxKeyPathBytes, keyTruncated);
	auto valueBytes = CopyNameW(valueScratch, valueName, MaxValueNameBytes, valueTruncated);
	auto copiedDataBytes = static_cast<ULONG>(min(dataLength, MaxValueDataBytes));

	auto pid = HandleToULong(PsGetCurrentProcessId());
	auto header = AllocRecord(RegistrySetValueFixed + keyBytes + valueBytes + copiedDataBytes,
		RegistrySetValue, pid, g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;
	if (keyTruncated)
		header->TruncFlags |= TRUNC_KEY_PATH;
	if (valueTruncated)
		header->TruncFlags |= TRUNC_VALUE_NAME;
	if (dataTruncated || dataLength > MaxValueDataBytes)
		header->TruncFlags |= TRUNC_DATA;

	auto record = reinterpret_cast<RegistrySetValueRecord*>(header);
	record->KeyPathOffset = RegistrySetValueFixed;
	record->KeyPathBytes = keyBytes;
	record->ValueNameOffset = record->KeyPathOffset + keyBytes;
	record->ValueNameBytes = valueBytes;
	record->DataType = dataType;
	record->DataBytes = copiedDataBytes;

	auto body = reinterpret_cast<UCHAR*>(header);
	::memcpy(body + record->KeyPathOffset, keyScratch, keyBytes);
	::memcpy(body + record->ValueNameOffset, valueScratch, valueBytes);
	if (copiedDataBytes > 0 && data)
		::memcpy(body + record->ValueNameOffset + valueBytes, data, copiedDataBytes);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
}

} // namespace

void InjectionEmitBehaviorCall(_In_ ULONG pid, _In_ ULONG64 createTime, _In_ ULONG threadId,
	_In_ ULONG api, _In_ ULONG64 arg0, _In_ ULONG64 arg1, _In_ ULONG64 arg2, _In_ ULONG64 arg3) {
	EmitBehaviorCallInternal(pid, createTime, threadId, api, arg0, arg1, arg2, arg3);
}

// Protection attribution (Protection.cpp): one stripped handle-open becomes
// a control-class record naming the opener and what was removed.
void ProtectionEmitStrippedEvent(_In_ ULONG openerPid, _In_ ULONG64 openerIdentity,
	_In_ ULONG protectedPid, _In_ ULONG64 protectedCreateTime, _In_ UCHAR targetIsThread,
	_In_ ULONG64 originalAccess, _In_ ULONG64 strippedAccess) {
	auto header = AllocRecord(ProtectionEventFixed, ProtectionEvent, openerPid, openerIdentity);
	if (header == nullptr)
		return;
	auto record = reinterpret_cast<ProtectionEventRecord*>(header);
	record->ProtectedPid = protectedPid;
	record->TargetIsThread = targetIsThread;
	record->ProtectedCreateTime = protectedCreateTime;
	record->OriginalDesiredAccess = originalAccess;
	record->StrippedAccess = strippedAccess;
	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
}


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	KdPrint((DRIVER_PREFIX "DriverEntry entered\n"));

	auto status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	bool processCallbacks = false, threadCallbacks = false, imageCallbacks = false, registryCallbacks = false;
	bool filterRegistered = false;
	bool obRegistered = false;

	// The malware is a user of this device: SYSTEM + Administrators only.
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

	do {
		UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\" SECOUTFALL_NAME);
		status = ::IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
			0, TRUE, &sddl, &GUID_DEVICECLASS_SECOUTFALL, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device object (status=%08X)\n", status));
			break;
		}

		UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" SECOUTFALL_NAME);
		status = ::IoCreateSymbolicLink(&symName, &deviceName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (status=%08X)\n", status));
			break;
		}

		g_Data.Identities = new (PagedPool) IdentityTable;
		g_Data.Identities->Init();
		g_Data.Watch = new (PagedPool) FileWatch;
		g_Data.Watch->Init();
		g_Data.Target = new (PagedPool) DropTarget;
		g_Data.Target->Init();
		g_Data.DropWatch = new (PagedPool) FileWatch;
		g_Data.DropWatch->Init();
		InjectionInit();
		ProtectionInit();
		g_Data.Drops = new (PagedPool) Queue<FastMutex>(512);
		g_Data.Items = new (PagedPool) Queue<FastMutex>(256, &g_Data.QueueOverwritten);
		// Flood class gets its own bounded list: a write storm must not evict
		// process evidence. Same drain, per-class overflow counters.
		g_Data.Files = new (PagedPool) Queue<FastMutex>(4096, &g_Data.FilesOverwritten);

		//
		// setup process, thread and image callbacks
		//
		status = ::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set process callbacks (status=%08X)\n", status));
			break;
		}
		processCallbacks = true;

		status = ::PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set thread callbacks (status=%08X)\n", status));
			break;
		}
		threadCallbacks = true;

		status = ::PsSetLoadImageNotifyRoutine(OnImageLoadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set image callbacks (status=%08X)\n", status));
			break;
		}
		imageCallbacks = true;

		//
		// setup registry callbacks
		//
		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"380088.01");
		status = ::CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr,
			&g_Data.RegistryCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register registry callbacks (status=%08X)\n", status));
			break;
		}
		registryCallbacks = true;

		//
		// register the minifilter (D2): file telemetry, same .sys, one drain
		//
		status = ::FltRegisterFilter(DriverObject, &FilterRegistration, &g_Data.Filter);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register minifilter (status=%08X)\n", status));
			break;
		}
		filterRegistered = true;

		// D4: ObCallbacks self-protection registration.
		status = ProtectionRegisterCallbacks(DriverObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register ob callbacks (status=%08X)\n", status));
			break;
		}
		obRegistered = true;

		// Starts attachment to the instances configured at install time
		// (Services\secoutfall\Instances — see driver/install.ps1).
		status = ::FltStartFiltering(g_Data.Filter);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to start filtering (status=%08X)\n", status));
			break;
		}

		DriverObject->DriverUnload = SecOutfallUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SecOutfallCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SecOutfallDeviceControl;
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (obRegistered)
			ProtectionUnregisterCallbacks();
		if (filterRegistered)
			::FltUnregisterFilter(g_Data.Filter);
		if (registryCallbacks)
			::CmUnRegisterCallback(g_Data.RegistryCookie);
		if (imageCallbacks)
			::PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
		if (threadCallbacks)
			::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
		if (processCallbacks)
			::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

		// A failed DriverEntry does not reclaim driver-tagged pool: the queue,
		// the identity table and the symbolic link must be unwound here, not
		// just at unload.
		if (g_Data.Items) {
			g_Data.Items->FreeAll<ItemFull<RecordHeader>>();
			delete g_Data.Items;
			g_Data.Items = nullptr;
		}
		if (g_Data.Identities) {
			g_Data.Identities->Clear();
			delete g_Data.Identities;
			g_Data.Identities = nullptr;
		}
		if (g_Data.Watch) {
			delete g_Data.Watch;
			g_Data.Watch = nullptr;
		}
		if (g_Data.Target) {
			g_Data.Target->Init();
			delete g_Data.Target;
			g_Data.Target = nullptr;
		}
		if (g_Data.DropWatch) {
			delete g_Data.DropWatch;
			g_Data.DropWatch = nullptr;
		}
		if (g_Data.Drops) {
			g_Data.Drops->FreeAll<ItemFull<RecordHeader>>();
			delete g_Data.Drops;
			g_Data.Drops = nullptr;
		}
		if (g_Data.Files) {
			g_Data.Files->FreeAll<ItemFull<RecordHeader>>();
			delete g_Data.Files;
			g_Data.Files = nullptr;
		}
		UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" SECOUTFALL_NAME);
		::IoDeleteSymbolicLink(&symName);

		if (DeviceObject)
			::IoDeleteDevice(DeviceObject);
		return status;
	}

	KdPrint((DRIVER_PREFIX "DriverEntry completed successfully\n"));

	return status;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR Information = 0) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

void SecOutfallUnload(PDRIVER_OBJECT DriverObject) {
	// Removals quiesce in-flight callbacks before returning; FltUnregisterFilter
	// likewise waits for file-system activity to drain before we free queues.
	ProtectionUnregisterCallbacks();
	ProtectionCleanup();
	InjectionCleanup();
	::CmUnRegisterCallback(g_Data.RegistryCookie);
	::PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
	::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	if (g_Data.Filter)
		::FltUnregisterFilter(g_Data.Filter);

	g_Data.Items->FreeAll<ItemFull<RecordHeader>>();
	delete g_Data.Items;
	g_Data.Files->FreeAll<ItemFull<RecordHeader>>();
	delete g_Data.Files;
	g_Data.Drops->FreeAll<ItemFull<RecordHeader>>();
	delete g_Data.Drops;
	if (g_Data.Watch)
		delete g_Data.Watch;
	if (g_Data.DropWatch)
		delete g_Data.DropWatch;
	if (g_Data.Target)
		delete g_Data.Target;
	g_Data.Identities->Clear();
	delete g_Data.Identities;

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" SECOUTFALL_NAME);
	::IoDeleteSymbolicLink(&symName);
	::IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS SecOutfallCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return CompleteRequest(Irp);
}

NTSTATUS SecOutfallDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG_PTR len = 0;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_SECOUTFALL_GET_DATA:
		{
			auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;
			// METHOD_OUT_DIRECT with a zero-length buffer carries no MDL — and
			// MmGetSystemAddressForMdlSafe dereferences the MDL pointer, so the
			// null check must come FIRST (NT_ASSERT compiles out in free
			// builds; every IOCTL is hostile input).
			if (size == 0 || Irp->MdlAddress == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto buffer = (UCHAR*)::MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			if (buffer == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			auto count = 0UL;
			// Merged drain over all three rate-class queues, ordered by the
			// global sequence: pop the globally-older head that fits; a head
			// that can never fit this client is skipped + counted; heads that
			// would fit a bigger batch stop this one.
			Queue<FastMutex>* queues[] = { g_Data.Items, g_Data.Files, g_Data.Drops };
			auto tryPop = [&](Queue<FastMutex>* queue) -> int {
				auto item = queue->PopIfFits<ItemFull<RecordHeader>>(size - count);
				if (item != nullptr) {
					auto recordSize = item->Item.Size;
					::memcpy(buffer + count, &item->Item, recordSize);
					count += recordSize;
					ExFreePool(item);
					return 1;
				}
				auto headSize = queue->HeadSize<ItemFull<RecordHeader>>();
				if (headSize == 0)
					return -1; // empty
				if (headSize > size) {
					item = queue->Pop<ItemFull<RecordHeader>>();
					ExFreePool(item);
					InterlockedIncrement64(&g_Data.OversizedSkipped);
					return 1;
				}
				return 0; // needs a bigger batch
			};
			while (true) {
				Queue<FastMutex>* oldest = nullptr;
				auto oldestSeq = MAXULONGLONG;
				for (auto queue : queues) {
					auto seq = queue->HeadSeq<ItemFull<RecordHeader>>();
					if (seq < oldestSeq) {
						oldestSeq = seq;
						oldest = queue;
					}
				}
				if (oldest == nullptr)
					break; // all empty
				auto progressed = false;
				if (tryPop(oldest) == 1) {
					progressed = true;
				} else {
					for (auto queue : queues) {
						if (queue == oldest)
							continue;
						if (tryPop(queue) == 1) {
							progressed = true;
							break;
						}
					}
				}
				if (!progressed)
					break; // every head needs a bigger buffer
			}
			len = count;
			break;
		}

		case IOCTL_SECOUTFALL_GET_STATS:
		{
			auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;
			// METHOD_BUFFERED: the payload arrives on the IRP, not the stack
			// location; length validated (hostile input).
			if (size < sizeof(DriverStats)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			auto stats = (DriverStats*)Irp->AssociatedIrp.SystemBuffer;
			stats->Magic = SECOUTFALL_WIRE_MAGIC;
			stats->Version = SECOUTFALL_WIRE_VERSION;
			stats->Reserved = 0;
			stats->QueueDepth = static_cast<ULONG>(g_Data.Items->GetCount());
			stats->QueueCapacity = static_cast<ULONG>(g_Data.Items->GetCapacity());
			stats->FileQueueDepth = static_cast<ULONG>(g_Data.Files->GetCount());
			stats->FileQueueCapacity = static_cast<ULONG>(g_Data.Files->GetCapacity());
			stats->Sequence = g_Data.NextSequence;
			stats->QueueOverwritten = g_Data.QueueOverwritten;
			stats->AllocFailures = g_Data.AllocFailures;
			stats->OversizedSkipped = g_Data.OversizedSkipped;
			stats->IdentityMisses = g_Data.IdentityMisses;
			stats->FilesOverwritten = g_Data.FilesOverwritten;
			stats->FileNameQueriesFailed = g_Data.FileNameQueriesFailed;
			stats->NoiseWritesSkipped = g_Data.NoiseWritesSkipped;
			stats->DropsQueueDepth = static_cast<ULONG>(g_Data.Drops->GetCount());
			stats->DropsQueueCapacity = static_cast<ULONG>(g_Data.Drops->GetCapacity());
			stats->DropsStopped = g_Data.DropsStopped;
			stats->DropsMissedBusy = g_Data.DropsMissedBusy;
			stats->DropsLinkFailed = g_Data.DropsLinkFailed;
			stats->DropsCopyFailed = g_Data.DropsCopyFailed;
			stats->InjectionsQueued = g_Data.InjectionsQueued;
			stats->InjectionsFailed = g_Data.InjectionsFailed;
			stats->SensorsRegistered = g_Data.SensorsRegistered;
			stats->SensorsRejected = g_Data.SensorsRejected;
			stats->SensorEventsDrained = g_Data.SensorEventsDrained;
			stats->SensorEventsDropped = g_Data.SensorEventsDropped;
			stats->SensorRingsActive = 0;
			{
				AutoLock<FastMutex> locker(*g_Data.InjectionLedgerLock);
				for (auto link = g_Data.InjectionLedger.Flink;
					link != &g_Data.InjectionLedger; link = link->Flink) {
					auto entry = CONTAINING_RECORD(link, InjectionEntry, Link);
					if (entry->State == InjectionState::Registered)
						++stats->SensorRingsActive;
				}
			}
			len = sizeof(DriverStats);
			break;
		}

		case IOCTL_SECOUTFALL_SET_FILE_WATCH:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (FileWatchPolicy*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength < sizeof(FileWatchPolicy)
				|| (input->Enabled > 1)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto blobBytes = input->ExtensionsBytes;
			if (blobBytes > FileWatch::MaxBlobBytes || blobBytes % 2 != 0
				|| input->ExtensionsCount > FileWatch::MaxExtensions
				|| inputLength < sizeof(FileWatchPolicy) + blobBytes) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (!input->Enabled || input->ExtensionsCount == 0) {
				// Off, or on-for-everything: both are single-switch policies.
				g_Data.Watch->Apply(input->Enabled != 0, nullptr, 0, nullptr, 0);
				break;
			}

			// Build the replacement off to the side; Apply swaps atomically and
			// keeps the old policy alive on any failure.
			auto blob = (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED, blobBytes, DRIVER_TAG);
			auto exts = (PUNICODE_STRING*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
				sizeof(PUNICODE_STRING) * input->ExtensionsCount, DRIVER_TAG);
			if (blob == nullptr || exts == nullptr) {
				if (blob) ExFreePool(blob);
				if (exts) ExFreePool(exts);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			::memcpy(blob, reinterpret_cast<UCHAR*>(input) + sizeof(FileWatchPolicy), blobBytes);

			ULONG count = 0;
			auto cursor = blob;
			auto end = blob + blobBytes / sizeof(WCHAR);
			auto parseOk = true;
			while (cursor < end && count < input->ExtensionsCount) {
				ULONG nameLen = 0;
				while (cursor + nameLen < end && cursor[nameLen] != L'\0')
					++nameLen;
				if (nameLen == 0 || cursor + nameLen >= end) {
					parseOk = false; // empty name or unterminated tail
					break;
				}
				auto entry = (PUNICODE_STRING)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
					sizeof(UNICODE_STRING), DRIVER_TAG);
				if (entry == nullptr) {
					parseOk = false;
					break;
				}
				entry->Buffer = cursor;
				entry->Length = static_cast<USHORT>(nameLen * sizeof(WCHAR));
				entry->MaximumLength = entry->Length;
				exts[count] = entry;
				++count;
				cursor += nameLen + 1; // skip the terminator
			}
			if (!parseOk || count != input->ExtensionsCount) {
				for (ULONG i = 0; i < count; ++i)
					ExFreePool(exts[i]);
				ExFreePool(exts);
				ExFreePool(blob);
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_Data.Watch->Apply(true, exts, count, blob, blobBytes);
			break;
		}

		case IOCTL_SECOUTFALL_SET_DROP_POLICY:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (DropPolicy*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength < sizeof(DropPolicy) || input->Enabled > 1) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto extBytes = input->ExtensionsBytes;
			auto dirBytes = input->DirBytes;
			if (extBytes > FileWatch::MaxBlobBytes || extBytes % 2 != 0
				|| input->ExtensionsCount > FileWatch::MaxExtensions
				|| dirBytes == 0 || dirBytes > DropTarget::MaxDirBytes || dirBytes % 2 != 0
				|| inputLength != sizeof(DropPolicy) + extBytes + dirBytes) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!input->Enabled) {
				g_Data.DropWatch->Apply(false, nullptr, 0, nullptr, 0);
				break;
			}

			auto payload = reinterpret_cast<UCHAR*>(input) + sizeof(DropPolicy);
			auto dirBlob = reinterpret_cast<PWCHAR>(payload + extBytes);

			// Validate the directory terminator before allocating anything.
			if (dirBlob[dirBytes / sizeof(WCHAR) - 1] != L'\0') {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			UNICODE_STRING dir;
			dir.Buffer = dirBlob;
			dir.Length = static_cast<USHORT>(dirBytes - sizeof(WCHAR)); // minus NUL
			dir.MaximumLength = dir.Length;
			if (!g_Data.Target->Apply(&dir)) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			// Extension list, same shape as SET_FILE_WATCH (NUL-terminated).
			auto exts = (PUNICODE_STRING*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
				sizeof(PUNICODE_STRING) * input->ExtensionsCount, DRIVER_TAG);
			auto extBlob = (PWCHAR)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
				extBytes ? extBytes : 2, DRIVER_TAG);
			if (exts == nullptr || extBlob == nullptr) {
				if (exts) ExFreePool(exts);
				if (extBlob) ExFreePool(extBlob);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			if (extBytes > 0)
				::memcpy(extBlob, payload, extBytes);
			ULONG count = 0;
			auto cursor = extBlob;
			auto end = extBlob + extBytes / sizeof(WCHAR);
			auto parseOk = true;
			while (cursor < end && count < input->ExtensionsCount) {
				ULONG nameLen = 0;
				while (cursor + nameLen < end && cursor[nameLen] != L'\0')
					++nameLen;
				if (nameLen == 0 || cursor + nameLen >= end) {
					parseOk = false;
					break;
				}
				auto entry = (PUNICODE_STRING)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
					sizeof(UNICODE_STRING), DRIVER_TAG);
				if (entry == nullptr) {
					parseOk = false;
					break;
				}
				entry->Buffer = cursor;
				entry->Length = static_cast<USHORT>(nameLen * sizeof(WCHAR));
				entry->MaximumLength = entry->Length;
				exts[count] = entry;
				++count;
				cursor += nameLen + 1;
			}
			if (!parseOk || count != input->ExtensionsCount) {
				for (ULONG i = 0; i < count; ++i)
					ExFreePool(exts[i]);
				ExFreePool(exts);
				ExFreePool(extBlob);
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_Data.DropWatch->Apply(true, exts, count, extBlob, extBytes);
			break;
		}

		case IOCTL_SECOUTFALL_SET_PROTECTED:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (ProtectionPolicy*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength < sizeof(ProtectionPolicy)
				|| input->Enabled > 1) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto namesBytes = input->NamesBytes;
			if (namesBytes > 4096 || namesBytes % 2 != 0
				|| inputLength != sizeof(ProtectionPolicy) + namesBytes) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (!input->Enabled) {
				ProtectionSetPolicy(false, nullptr);
				break;
			}
			UNICODE_STRING names;
			names.Buffer = reinterpret_cast<PWCH>(
				reinterpret_cast<UCHAR*>(input) + sizeof(ProtectionPolicy));
			names.Length = static_cast<USHORT>(namesBytes);
			names.MaximumLength = names.Length;
			if (!ProtectionSetPolicy(true, &names))
				status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		case IOCTL_SECOUTFALL_SET_DEVICE_SECURITY:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (DeviceSecurityBlob*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength < sizeof(DeviceSecurityBlob)
				|| input->Enabled > 1) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto sdBytes = input->SdBytes;
			if (sdBytes == 0 || sdBytes > 4096
				|| inputLength != sizeof(DeviceSecurityBlob) + sdBytes) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (!input->Enabled) {
				// Disabling re-applies the compiled SDDL by recreating the
				// security descriptor: simplest honest v1 is to reject the
				// disable (the agent simply never sends it).
				status = STATUS_NOT_SUPPORTED;
				break;
			}
			status = ProtectionSetDeviceSecurity(DeviceObject,
				reinterpret_cast<UCHAR*>(input) + sizeof(DeviceSecurityBlob), sdBytes);
			break;
		}

		case IOCTL_SECOUTFALL_SET_INJECTION_POLICY:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (InjectionPolicy*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength < sizeof(InjectionPolicy)
				|| input->Enabled > 1) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto pathBytes = input->DllPathBytes;
			auto exclBytes = input->ExclusionsBytes;
			if (pathBytes < 2 * sizeof(WCHAR) || pathBytes % 2 != 0
				|| exclBytes % 2 != 0
				|| inputLength != sizeof(InjectionPolicy) + pathBytes + exclBytes) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto payload = reinterpret_cast<UCHAR*>(input) + sizeof(InjectionPolicy);
			UNICODE_STRING dllPath;
			dllPath.Buffer = reinterpret_cast<PWCH>(payload);
			dllPath.Length = static_cast<USHORT>(pathBytes - sizeof(WCHAR)); // minus NUL
			dllPath.MaximumLength = dllPath.Length;
			UNICODE_STRING exclusions;
			exclusions.Buffer = reinterpret_cast<PWCH>(payload + pathBytes);
			exclusions.Length = static_cast<USHORT>(exclBytes);
			exclusions.MaximumLength = exclusions.Length;
			if (!InjectionSetPolicy(input->Enabled != 0, &dllPath,
				exclBytes > 0 ? &exclusions : nullptr)) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			break;
		}

		case IOCTL_SECOUTFALL_SENSOR_CHALLENGE:
		{
			auto outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
			if (outLength != sizeof(SensorChallenge)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto challenge = (SensorChallenge*)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS caller = nullptr;
			if (!NT_SUCCESS(::PsLookupProcessByProcessId(PsGetCurrentProcessId(), &caller))) {
				status = STATUS_ACCESS_DENIED;
				break;
			}
			auto ok = InjectionSensorChallenge(HandleToULong(PsGetCurrentProcessId()),
				caller, challenge);
			ObDereferenceObject(caller);
			if (!ok) {
				status = STATUS_ACCESS_DENIED;
				len = 0;
				break;
			}
			len = sizeof(SensorChallenge);
			break;
		}

		case IOCTL_SECOUTFALL_SENSOR_REGISTER:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (SensorRegister*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength != sizeof(SensorRegister)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (!InjectionSensorRegister(HandleToULong(PsGetCurrentProcessId()),
				input->Nonce, input->Version)) {
				status = STATUS_ACCESS_DENIED;
				break;
			}
			break;
		}

		case IOCTL_SECOUTFALL_SELFTEST_FLOOD:
		{
			auto inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
			auto input = (SelftestFloodRequest*)Irp->AssociatedIrp.SystemBuffer;
			if (input == nullptr || inputLength != sizeof(SelftestFloodRequest)
				|| input->Class > 1 || input->Count == 0 || input->Count > 100000) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto fileClass = input->Class == 1;
			for (ULONG i = 0; i < input->Count; ++i) {
				ULONG pid = 0xDEAD0000u + i;
				if (!fileClass) {
					auto header = AllocRecord(ProcessExitedFixed, ProcessExited, pid, 0);
					if (header == nullptr)
						break; // alloc failures are counted in AllocRecord
					PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
				} else {
					PCUNICODE_STRING floodPath;
					UNICODE_STRING floodName = RTL_CONSTANT_STRING(L"\\??\\flood");
					floodPath = &floodName;
					bool truncated = false;
					WCHAR scratch[MaxFilePathBytes / sizeof(WCHAR)];
					auto pathBytes = CopyNameW(scratch, floodPath, MaxFilePathBytes, truncated);
					auto header = AllocRecord(FileWrittenFixed + pathBytes, FileWritten, pid, 0);
					if (header == nullptr)
						break;
					auto record = reinterpret_cast<FileWrittenRecord*>(header);
					record->ByteOffset = i;
					record->BytesCount = 1;
					record->PathOffset = FileWrittenFixed;
					record->PathBytes = pathBytes;
					::memcpy(reinterpret_cast<UCHAR*>(header) + record->PathOffset, scratch, pathBytes);
					PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
				}
			}
			break;
		}

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	return CompleteRequest(Irp, status, len);
}

void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo) {
		//
		// process created: the witnessed creation time doubles as the
		// identity token, so it is assigned here and tracked until exit.
		//
		bool cmdTruncated = false;
		WCHAR cmdScratch[MaxCommandLineBytes / sizeof(WCHAR)];
		auto cmdBytes = CopyNameW(cmdScratch, CreateInfo->CommandLine, MaxCommandLineBytes, cmdTruncated);

		auto pid = HandleToULong(ProcessId);
		auto header = AllocRecord(ProcessCreatedFixed + cmdBytes, ProcessCreated, pid, 0);
		if (header == nullptr)
			return;
		auto createTime = header->Time;
		if (cmdTruncated)
			header->TruncFlags |= TRUNC_CMDLINE;

		auto record = reinterpret_cast<ProcessCreatedRecord*>(header);
		record->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
		record->CommandLineOffset = cmdBytes > 0 ? ProcessCreatedFixed : 0;
		record->CommandLineBytes = cmdBytes;
		if (cmdBytes > 0)
			::memcpy(reinterpret_cast<UCHAR*>(header) + record->CommandLineOffset, cmdScratch, cmdBytes);

		// Track identity regardless of queue pressure: scope correctness
		// outweighs telemetry completeness.
		if (!g_Data.Identities->Insert(pid, createTime))
			NextIdentityMiss();

		PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));

		// D3: universal sensor injection (engine applies its own blocklist).
		InjectionOnProcessCreate(pid, createTime, CreateInfo->ImageFileName);

		// D4: protect our own processes (name policy + ObCallbacks table).
		ProtectionOnProcessCreate(pid, createTime, CreateInfo->ImageFileName);
	}
	else {
		//
		// process destroyed: carry the identity out before removing it.
		//
		auto pid = HandleToULong(ProcessId);
		auto createTime = g_Data.Identities->Lookup(pid);
		if (createTime == 0)
			NextIdentityMiss();
		g_Data.Identities->Remove(pid);
		InjectionOnProcessExit(pid);
		ProtectionOnProcessExit(pid);

		auto header = AllocRecord(ProcessExitedFixed, ProcessExited, pid, createTime);
		if (header == nullptr)
			return;

		PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
	}
}

void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
	auto pid = HandleToULong(ProcessId);
	auto header = AllocRecord(ThreadFixed, Create ? ThreadCreated : ThreadExited,
		pid, g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;

	auto record = reinterpret_cast<ThreadRecord*>(header);
	record->ThreadId = HandleToULong(ThreadId);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));

	// D3: the FIRST thread of a process is the injection target (an APC
	// queued before it runs is delivered during loader init, before any
	// user code). Later threads are irrelevant to the engine.
	if (Create) {
		PETHREAD thread = nullptr;
		if (NT_SUCCESS(::PsLookupThreadByThreadId(ThreadId, &thread))) {
			InjectionOnFirstThread(pid, thread);
			ObDereferenceObject(thread);
		}
	}
}

void OnImageLoadNotify(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
	// Kernel-mode images (drivers, including ours) are telemetry noise here —
	// the sandbox analyzes user-mode behavior.
	if (ImageInfo->SystemModeImage)
		return;

	// D3: ntdll base capture + LdrLoadDll RVA resolution + injection trigger.
	InjectionOnImageLoad(HandleToULong(ProcessId), ImageInfo->ImageBase, FullImageName);

	bool nameTruncated = false;
	WCHAR nameScratch[MaxImageNameBytes / sizeof(WCHAR)];
	auto nameBytes = CopyNameW(nameScratch, FullImageName, MaxImageNameBytes, nameTruncated);

	auto pid = HandleToULong(ProcessId);
	auto header = AllocRecord(ImageLoadedFixed + nameBytes, ImageLoaded,
		pid, g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return;
	if (nameTruncated)
		header->TruncFlags |= TRUNC_IMAGE_NAME;

	auto record = reinterpret_cast<ImageLoadedRecord*>(header);
	record->ImageBase = reinterpret_cast<ULONG64>(ImageInfo->ImageBase);
	// The 26100 WDK widens IMAGE_INFO.ImageSize to SIZE_T; the wire field is
	// ULONG by design (per-image sizes are far below 4 GiB).
	record->ImageSize = static_cast<ULONG>(ImageInfo->ImageSize);
	record->NameOffset = ImageLoadedFixed;
	record->NameBytes = nameBytes;
	if (nameBytes > 0)
		::memcpy(reinterpret_cast<UCHAR*>(header) + record->NameOffset, nameScratch, nameBytes);

	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item));
}

NTSTATUS OnRegistryNotify(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2) {
	UNREFERENCED_PARAMETER(CallbackContext);

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1) {
		case RegNtPostSetValueKey:
		{
			auto args = static_cast<REG_POST_OPERATION_INFORMATION*>(Argument2);
			if (!NT_SUCCESS(args->Status))
				break;
			if (auto path = GetKeyPath(args->Object)) {
				if (IsMachineKey(path)) {
					auto preInfo = static_cast<REG_SET_VALUE_KEY_INFORMATION*>(args->PreInformation);
					if (preInfo && preInfo->ValueName && preInfo->Data)
						EmitRegistrySetValue(path, preInfo->ValueName, preInfo->Type,
							preInfo->Data, static_cast<ULONG>(preInfo->DataSize));
				}
				::CmCallbackReleaseKeyObjectIDEx(path);
			}
			break;
		}

		case RegNtPostCreateKeyEx:
		{
			auto args = static_cast<REG_POST_CREATE_KEY_INFORMATION*>(Argument2);
			if (!NT_SUCCESS(args->Status))
				break;
			if (auto path = GetKeyPath(args->Object)) {
				if (IsMachineKey(path))
					EmitRegistryKeyRecord(RegistryKeyCreated, path);
				::CmCallbackReleaseKeyObjectIDEx(path);
			}
			break;
		}

		case RegNtPostDeleteKey:
		{
			auto args = static_cast<REG_POST_OPERATION_INFORMATION*>(Argument2);
			if (!NT_SUCCESS(args->Status))
				break;
			// The object is mid-teardown in the post callback; a failed name
			// lookup skips the record rather than emit a nameless one.
			if (auto path = GetKeyPath(args->Object)) {
				if (IsMachineKey(path))
					EmitRegistryKeyRecord(RegistryKeyDeleted, path);
				::CmCallbackReleaseKeyObjectIDEx(path);
			}
			break;
		}

		default:
			break;
	}

	return STATUS_SUCCESS;
}

//
// Minifilter callbacks (D2): post-op telemetry only, observe-only. File
// telemetry is OFF until SET_FILE_WATCH enables it; every record still pays
// identity lookup, caps and truncation flags like the control class.
//

FLT_PREOP_CALLBACK_STATUS FLTAPI SecOutfallPreSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PVOID* NewCompletionContext) {
	UNREFERENCED_PARAMETER(FltObjects);
	*NewCompletionContext = nullptr;

	auto cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	if (cls != FileRenameInformation && cls != FileRenameInformationEx)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (!g_Data.Watch->Enabled() || KeGetCurrentIrql() > APC_LEVEL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// The pre-rename name only exists NOW: post-rename queries return the
	// new name. Capture it into a nonpaged context for the post callback.
	PFLT_FILE_NAME_INFORMATION name = nullptr;
	if (!NT_SUCCESS(::FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
		InterlockedIncrement64(&g_Data.FileNameQueriesFailed);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	auto bytes = static_cast<USHORT>(min(name->Name.Length, MaxFilePathBytes));
	bytes &= static_cast<USHORT>(~1);
	auto context = (RenameContext*)::ExAllocatePool2(POOL_FLAG_NON_PAGED,
		sizeof(RenameContext) + bytes, DRIVER_TAG);
	if (context == nullptr) {
		InterlockedIncrement64(&g_Data.AllocFailures);
		::FltReleaseFileNameInformation(name);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	context->OldPath.Buffer = reinterpret_cast<PWCHAR>(context + 1);
	context->OldPath.Length = bytes;
	context->OldPath.MaximumLength = bytes;
	::memcpy(context->OldPath.Buffer, name->Name.Buffer, bytes);
	::FltReleaseFileNameInformation(name);

	*NewCompletionContext = context;
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (FLT_IS_FASTIO_OPERATION(Data) || FLT_IS_FS_FILTER_OPERATION(Data))
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (!g_Data.Watch->Enabled() || !NT_SUCCESS(Data->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;
	// IoStatus.Information after create: FILE_SUPERSEDED / FILE_CREATED /
	// FILE_OPENED / FILE_OVERWRITTEN / FILE_OVERWRITTEN_OR_CREATED — only
	// the first two mean a NEW file came into existence.
	if (Data->IoStatus.Information != FILE_SUPERSEDED && Data->IoStatus.Information != FILE_CREATED)
		return FLT_POSTOP_FINISHED_PROCESSING;

	auto name = QueryFileName(Data);
	if (name == nullptr)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (g_Data.Watch->Matches(&name->Name))
		EmitFileRecord(FileCreated, &name->Name, HandleToULong(PsGetCurrentProcessId()));
	::FltReleaseFileNameInformation(name);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostWrite(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	// Paging-IO writes (cache flushes, not thread writes) never reach this
	// callback: skipped at registration via FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO.
	if (!g_Data.Watch->Enabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	auto length = Data->Iopb->Parameters.Write.Length;
	auto offset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
	if (length == 0)
		return FLT_POSTOP_FINISHED_PROCESSING;
	// Write-noise heuristic (carried from the reference implementation):
	// whole-cache-page writes at a non-zero offset are antivirus-style cache
	// touches, not drops.
	if ((length == 4096 || length == 8192 || length == 16384) && offset > 0) {
		InterlockedIncrement64(&g_Data.NoiseWritesSkipped);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	auto name = QueryFileName(Data);
	if (name == nullptr)
		return FLT_POSTOP_FINISHED_PROCESSING;
	auto pid = HandleToULong(PsGetCurrentProcessId());
	if (g_Data.Watch->Matches(&name->Name)) {
		bool truncated = false;
		WCHAR scratch[MaxFilePathBytes / sizeof(WCHAR)];
		auto pathBytes = CopyNameW(scratch, &name->Name, MaxFilePathBytes, truncated);
		auto header = AllocRecord(FileWrittenFixed + pathBytes, FileWritten, pid,
			g_Data.Identities->Lookup(pid));
		if (header != nullptr) {
			if (truncated)
				header->TruncFlags |= TRUNC_FILE_PATH;
			auto record = reinterpret_cast<FileWrittenRecord*>(header);
			record->ByteOffset = static_cast<ULONG64>(offset);
			record->BytesCount = length;
			record->PathOffset = FileWrittenFixed;
			record->PathBytes = pathBytes;
			::memcpy(reinterpret_cast<UCHAR*>(header) + record->PathOffset, scratch, pathBytes);
			PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
		}
	}

	// Drop capture (D2b): same name, its own extension policy, exactly-once
	// per stream via the context.
	TryCaptureDrop(FltObjects->Instance, Data, &name->Name, pid);

	::FltReleaseFileNameInformation(name);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostCleanup(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (FLT_IS_FASTIO_OPERATION(Data) || FLT_IS_FS_FILTER_OPERATION(Data))
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (!g_Data.Watch->Enabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	auto name = QueryFileName(Data);
	if (name == nullptr)
		return FLT_POSTOP_FINISHED_PROCESSING;
	auto pid = HandleToULong(PsGetCurrentProcessId());
	if (g_Data.Watch->Matches(&name->Name))
		EmitFileRecord(FileCleanedUp, &name->Name, pid);
	TryCleanupCopy(FltObjects->Instance, Data, &name->Name, pid);
	::FltReleaseFileNameInformation(name);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI SecOutfallPostSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	auto context = static_cast<RenameContext*>(CompletionContext);
	auto cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	auto isDelete = cls == FileDispositionInformation || cls == FileDispositionInformationEx;
	auto isRename = cls == FileRenameInformation || cls == FileRenameInformationEx;
	if (!isDelete && !isRename)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		if (context)
			ExFreePool(context);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (!g_Data.Watch->Enabled()) {
		if (context)
			ExFreePool(context);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	auto name = QueryFileName(Data);
	if (name == nullptr) {
		if (context)
			ExFreePool(context);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	auto pid = HandleToULong(PsGetCurrentProcessId());
	if (isDelete) {
		if (g_Data.Watch->Matches(&name->Name))
			EmitFileRecord(FileDeleted, &name->Name, pid);
	} else {
		// No context = the old path never made it out of the pre callback
		// (query failed there and was counted); skip rather than emit a
		// rename with a fabricated origin.
		if (context != nullptr && g_Data.Watch->Matches(&name->Name))
			EmitFileRenamed(context, &name->Name, pid);
	}

	::FltReleaseFileNameInformation(name);
	if (context)
		ExFreePool(context);
	return FLT_POSTOP_FINISHED_PROCESSING;
}
