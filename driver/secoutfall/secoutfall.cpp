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

Globals g_Data;

// Device setup class GUID for the secure device creation (unique per driver).
const GUID GUID_DEVICECLASS_SECOUTFALL = {
	0xb7a9e2d1, 0x4c3f, 0x4e8b, { 0x9a, 0x6d, 0x15, 0xf2, 0xc8, 0xe7, 0xb4, 0xa0 }
};

namespace {

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

void PushRecord(_Inout_ ItemFull<RecordHeader>* item) {
	g_Data.Items->Push(item);
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
		g_Data.Items = new (PagedPool) Queue<FastMutex>(256, &g_Data.QueueOverwritten);

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

		DriverObject->DriverUnload = SecOutfallUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SecOutfallCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SecOutfallDeviceControl;
	} while (false);

	if (!NT_SUCCESS(status)) {
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
	// Removals quiesce in-flight callbacks before returning, so the queue and
	// the identity table are producer-free below.
	::CmUnRegisterCallback(g_Data.RegistryCookie);
	::PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
	::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

	g_Data.Items->FreeAll<ItemFull<RecordHeader>>();
	delete g_Data.Items;
	if (g_Data.Identities) {
		g_Data.Identities->Clear();
		delete g_Data.Identities;
		g_Data.Identities = nullptr;
	}

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
			while (true) {
				// Check-and-pop under one lock: peeking and popping separately
				// let two concurrent drains validate one item and pop another
				// (size from X, bytes from Y — a pool over-read and a corrupt
				// record stream). A head that fits goes out; one that does not
				// fit the REMAINING space stops this batch; one that cannot fit
				// ANY buffer this client ever sends is skipped and counted — a
				// wedged queue is a worse fate than a lost oversized record.
				auto item = g_Data.Items->PopIfFits<ItemFull<RecordHeader>>(size - count);
				if (item != nullptr) {
					auto recordSize = item->Item.Size;
					::memcpy(buffer + count, &item->Item, recordSize);
					count += recordSize;
					ExFreePool(item);
					continue;
				}

				auto headSize = g_Data.Items->HeadSize<ItemFull<RecordHeader>>();
				if (headSize == 0)
					break; // drained empty
				if (headSize > size) {
					item = g_Data.Items->Pop<ItemFull<RecordHeader>>();
					ExFreePool(item);
					InterlockedIncrement64(&g_Data.OversizedSkipped);
					continue;
				}
				break; // head needs a bigger buffer; leave it queued
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
			stats->Sequence = g_Data.NextSequence;
			stats->QueueOverwritten = g_Data.QueueOverwritten;
			stats->AllocFailures = g_Data.AllocFailures;
			stats->OversizedSkipped = g_Data.OversizedSkipped;
			stats->IdentityMisses = g_Data.IdentityMisses;
			len = sizeof(DriverStats);
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
