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

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),   // Size
	FLT_REGISTRATION_VERSION,   // Version
	0,                          // Flags
	nullptr,                    // Context
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

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	KdPrint((DRIVER_PREFIX "DriverEntry entered\n"));

	auto status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	bool processCallbacks = false, threadCallbacks = false, imageCallbacks = false, registryCallbacks = false;
	bool filterRegistered = false;

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
	if (g_Data.Watch)
		delete g_Data.Watch;
	g_Data.Identities->Clear();
	delete g_Data.Identities;

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" SECOUTFALL_NAME);
	::IoDeleteSymbolicLink(&symName);
	::IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS SecOutfallCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return CompleteRequest(Irp);
}

NTSTATUS SecOutfallDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
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
			// Merged drain over both rate-class queues, ordered by the global
			// sequence: pop the globally-older head that fits; a head that can
			// never fit this client is skipped + counted; heads that would fit
			// a bigger batch stop this one.
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
				auto seqControl = g_Data.Items->HeadSeq<ItemFull<RecordHeader>>();
				auto seqFiles = g_Data.Files->HeadSeq<ItemFull<RecordHeader>>();
				if (seqControl == MAXULONGLONG && seqFiles == MAXULONGLONG)
					break;
				auto first = (seqFiles < seqControl) ? g_Data.Files : g_Data.Items;
				auto second = (first == g_Data.Files) ? g_Data.Items : g_Data.Files;
				if (tryPop(first) == 1)
					continue;
				if (tryPop(second) == 1)
					continue;
				break; // both heads need a bigger buffer
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
}

void OnImageLoadNotify(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
	// Kernel-mode images (drivers, including ours) are telemetry noise here —
	// the sandbox analyzes user-mode behavior.
	if (ImageInfo->SystemModeImage)
		return;

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
	if (!g_Data.Watch->Matches(&name->Name)) {
		::FltReleaseFileNameInformation(name);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	bool truncated = false;
	WCHAR scratch[MaxFilePathBytes / sizeof(WCHAR)];
	auto pathBytes = CopyNameW(scratch, &name->Name, MaxFilePathBytes, truncated);
	::FltReleaseFileNameInformation(name);

	auto pid = HandleToULong(PsGetCurrentProcessId());
	auto header = AllocRecord(FileWrittenFixed + pathBytes, FileWritten, pid,
		g_Data.Identities->Lookup(pid));
	if (header == nullptr)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (truncated)
		header->TruncFlags |= TRUNC_FILE_PATH;
	auto record = reinterpret_cast<FileWrittenRecord*>(header);
	record->ByteOffset = static_cast<ULONG64>(offset);
	record->BytesCount = length;
	record->PathOffset = FileWrittenFixed;
	record->PathBytes = pathBytes;
	::memcpy(reinterpret_cast<UCHAR*>(header) + record->PathOffset, scratch, pathBytes);
	PushRecord(CONTAINING_RECORD(header, ItemFull<RecordHeader>, Item), true);
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
	if (g_Data.Watch->Matches(&name->Name))
		EmitFileRecord(FileCleanedUp, &name->Name, HandleToULong(PsGetCurrentProcessId()));
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
