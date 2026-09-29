// secoutfall — D0 process/thread/registry telemetry skeleton, adapted from
// the WKP SysMon base (Pavel Yosifovich, Windows Kernel Programming).
//
// D0 deltas vs the base: renamed, secure device creation (SDDL: SYSTEM +
// Administrators only), ExAllocatePool2 allocations, clamped command-line
// capture (the base could overflow `short Size`), clamped registry name
// copies (the base memcpied attacker-controlled lengths into fixed buffers).
// The full hardening list and phase plan live in the repo AGENTS.md.

#include "pch.h"
#include "secoutfallCommon.h"
#include "secoutfall.h"
#include "Memory.h"

DRIVER_UNLOAD SecOutfallUnload;
DRIVER_DISPATCH SecOutfallCreateClose;
DRIVER_DISPATCH SecOutfallDeviceControl;

void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
NTSTATUS OnRegistryNotify(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2);

Globals g_Data;

// Device setup class GUID for the secure device creation (unique per driver).
const GUID GUID_DEVICECLASS_SECOUTFALL = {
	0xb7a9e2d1, 0x4c3f, 0x4e8b, { 0x9a, 0x6d, 0x15, 0xf2, 0xc8, 0xe7, 0xb4, 0xa0 }
};

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	KdPrint((DRIVER_PREFIX "DriverEntry entered\n"));

	auto status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	bool processCallbacks = false, threadCallbacks = false, registryCallbacks = false;

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

		g_Data.Items = new (PagedPool) Queue<FastMutex>(256);

		//
		// setup process and thread callbacks
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

		//
		// setup registry callbacks
		//
		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"380088.01");
		status = ::CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr,
			&g_Data.RegistryCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register registry callbacks (status=%08X)\n", status));
		}
		else {
			registryCallbacks = true;
		}

		DriverObject->DriverUnload = SecOutfallUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SecOutfallCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SecOutfallDeviceControl;
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (registryCallbacks)
			::CmUnRegisterCallback(g_Data.RegistryCookie);
		if (threadCallbacks)
			::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
		if (processCallbacks)
			::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

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
	::CmUnRegisterCallback(g_Data.RegistryCookie);
	::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

	g_Data.Items->FreeAll<ItemFull<ItemHeader>>();
	delete g_Data.Items;

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
			NT_ASSERT(Irp->MdlAddress);

			auto buffer = (UCHAR*)::MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;
			if (buffer == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			auto count = 0UL;
			while (true) {
				auto next = g_Data.Items->Peek<ItemFull<ItemHeader>>();
				if (next == nullptr)
					break;
				auto nextSize = (ULONG)next->Item.Size;
				if (nextSize > size - count)
					break;
				auto item = g_Data.Items->Pop<ItemFull<ItemHeader>>();
				::memcpy(buffer + count, &item->Item, nextSize);
				count += nextSize;

				// free the item, it's no longer needed
				ExFreePool(item);
			}
			len = count;
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
		// process created
		//
		USHORT cmdBytes = 0;
		if (CreateInfo->CommandLine) {
			cmdBytes = static_cast<USHORT>(CreateInfo->CommandLine->Length);
			if (cmdBytes > MaxCommandLineBytes)
				cmdBytes = MaxCommandLineBytes;
			cmdBytes &= static_cast<USHORT>(~1); // whole WCHARs only
		}

		auto info = (ItemFull<ProcessCreateInfo>*)::ExAllocatePool2(POOL_FLAG_PAGED,
			sizeof(ItemFull<ProcessCreateInfo>) + cmdBytes, DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
			return;
		}

		ProcessCreateInfo& item = info->Item;
		::KeQuerySystemTimePrecise(&item.Time);
		item.Type = ItemType::ProcessCreated;
		item.ProcessId = HandleToULong(ProcessId);
		item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
		item.CommandLineOffset = (short)sizeof(ProcessCreateInfo);
		item.CommandLineLength = (short)(cmdBytes / sizeof(WCHAR));
		if (cmdBytes > 0)
			::memcpy((UCHAR*)&item + sizeof(item), CreateInfo->CommandLine->Buffer, cmdBytes);
		item.Size = (short)(sizeof(ProcessCreateInfo) + cmdBytes);
		g_Data.Items->Push(info);
	}
	else {
		//
		// process destroyed
		//
		auto info = (ItemFull<ProcessExitInfo>*)::ExAllocatePool2(POOL_FLAG_PAGED,
			sizeof(ItemFull<ProcessExitInfo>), DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
			return;
		}

		auto& item = info->Item;
		::KeQuerySystemTimePrecise(&item.Time);
		item.Size = (short)sizeof(item);
		item.Type = ItemType::ProcessExited;
		item.ProcessId = HandleToULong(ProcessId);
		g_Data.Items->Push(info);
	}
}

void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
	auto info = (ItemFull<ThreadCreateExitInfo>*)::ExAllocatePool2(POOL_FLAG_PAGED,
		sizeof(ItemFull<ThreadCreateExitInfo>), DRIVER_TAG);
	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
		return;
	}
	auto& item = info->Item;
	::KeQuerySystemTimePrecise(&item.Time);
	item.Size = (short)sizeof(item);
	item.Type = Create ? ItemType::ThreadCreated : ItemType::ThreadExited;
	item.ProcessId = HandleToULong(ProcessId);
	item.ThreadId = HandleToULong(ThreadId);

	g_Data.Items->Push(info);
}

NTSTATUS OnRegistryNotify(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2) {
	UNREFERENCED_PARAMETER(CallbackContext);

	static const WCHAR machine[] = L"\\REGISTRY\\MACHINE";

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1) {
		case RegNtPostSetValueKey:
		{
			auto args = static_cast<REG_POST_OPERATION_INFORMATION*>(Argument2);
			PCUNICODE_STRING name = nullptr;
			if (!NT_SUCCESS(::CmCallbackGetKeyObjectIDEx(&g_Data.RegistryCookie, args->Object, nullptr, &name, 0)))
				break;

			// filter out non-HKLM writes
			if (::wcsncmp(name->Buffer, machine, ARRAYSIZE(machine) - 1) == 0) {
				auto preInfo = (REG_SET_VALUE_KEY_INFORMATION*)args->PreInformation;
				if (preInfo && preInfo->ValueName && preInfo->Data) {
					auto info = (ItemFull<RegistrySetValueInfo>*)::ExAllocatePool2(POOL_FLAG_PAGED,
						sizeof(ItemFull<RegistrySetValueInfo>), DRIVER_TAG);
					if (info != nullptr) {
						RtlZeroMemory(info, sizeof(ItemFull<RegistrySetValueInfo>));
						auto& item = info->Item;
						::KeQuerySystemTimePrecise(&item.Time);
						item.Size = (short)sizeof(item);
						item.Type = ItemType::RegistrySetValue;
						// attacker-controlled lengths: clamp to the fixed buffers,
						// the zeroed remainder keeps the names NUL-terminated
						::memcpy(item.KeyName, name->Buffer, min(name->Length, sizeof(item.KeyName)));
						::memcpy(item.ValueName, preInfo->ValueName->Buffer,
							min(preInfo->ValueName->Length, sizeof(item.ValueName)));
						item.DataType = preInfo->Type;
						item.DataSize = (ULONG)preInfo->DataSize;
						item.ProcessId = HandleToULong(PsGetCurrentProcessId());
						::memcpy(item.Data, preInfo->Data, min(item.DataSize, sizeof(item.Data)));

						g_Data.Items->Push(info);
					}
				}
			}

			::CmCallbackReleaseKeyObjectIDEx(name);
			break;
		}

		default:
			break;
	}

	return STATUS_SUCCESS;
}
