#pragma once

// D4 self-protection: ObCallbacks handle-stripping for protected processes.
//
// Protected processes are selected BY NAME via SETPROTECTED (our own agent
// + user-actor in practice). Matching processes are tracked in a pid table
// (process-create/exit hooks); the Ob pre-operation callback then strips
// dangerous access (terminate / VM write / VM read / create-thread /
// duplicate / suspend-set) from handles opened by UNPROTECTED callers —
// protected processes can still manage each other, and the System process
// is always trusted.
//
// Every strip is also an attack-attribution wire record (drops-class? no:
// control-class — security evidence is scarce by definition). The callback
// runs at <= APC_LEVEL for our purposes; record allocation is nonpaged, so
// no IRQL surprises.
//
// Device security: SET_DEVICE_SECURITY replaces the device DACL with a
// caller-built raw self-relative SD (the D5 agent pushes a console-user ACE
// so the injected sensor can reach the control device from non-elevated
// targets; lab runs elevated and never needs it).

#include "pch.h"

void ProtectionInit();
void ProtectionCleanup();
// Replaces the protected-name list (NUL-terminated wide blob). Returns
// false on allocation failure (the previous list stays).
bool ProtectionSetPolicy(_In_ bool enabled, _In_ PCUNICODE_STRING names);
// Process-create/exit hooks: maintain the protected pid table.
void ProtectionOnProcessCreate(_In_ ULONG pid, _In_ ULONG64 createTime,
	_In_opt_ PCUNICODE_STRING imageFileName);
void ProtectionOnProcessExit(_In_ ULONG pid);
// Registers/unregisters the ObCallbacks (call from DriverEntry/Unload).
NTSTATUS ProtectionRegisterCallbacks(_In_ PDRIVER_OBJECT driverObject);
void ProtectionUnregisterCallbacks();
// Applies a raw self-relative security descriptor to the control device.
NTSTATUS ProtectionSetDeviceSecurity(_In_ PDEVICE_OBJECT device, _In_ PUCHAR sdBytes, _In_ ULONG sdLength);

// Implemented in secoutfall.cpp (owns the record allocator + queues): the
// attribution record for one stripped handle-open. PASSIVE-only callers.
void ProtectionEmitStrippedEvent(_In_ ULONG openerPid, _In_ ULONG64 openerIdentity,
	_In_ ULONG protectedPid, _In_ ULONG64 protectedCreateTime, _In_ UCHAR targetIsThread,
	_In_ ULONG64 originalAccess, _In_ ULONG64 strippedAccess);
