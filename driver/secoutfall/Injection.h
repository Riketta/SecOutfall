#pragma once

// D3 injection engine: universal user-APC injection of the sensor DLL into
// every newly created process minus the blocklist, with lazy activation —
// the sensor registers with a per-injection nonce (anti-impersonation) and
// stays idle until the driver flips it to active.
//
// Flow (state in the ledger, lock-guarded):
//   process create   -> PendingThread   (identity + nonce minted)
//   first thread     -> PendingThread -> PendingNtdll (ntdll not seen yet)
//                        or straight to Ready when ntdll is already present
//   ntdll image load -> Pending*     -> Ready
//   both present     -> APC queued (Injected), CAS from Ready
//   sensor register  -> Registered    (nonce echoed; one-shot)
//   process exit     -> entry removed
//
// The APC routine is a 20-byte stub written into the target: it bridges the
// user-APC single argument to LdrLoadDll's four (see InjectStubBytes).
//
// Known, accepted v1 limits:
//   - PPL targets: the kernel-side allocation works, the in-target
//     LdrLoadDll fails code-integrity checks — harmless, counted.
//   - WOW64: the x64 sensor loads into the x64 side of WOW64 processes;
//     full WOW64 hooking is a later decision.
//   - Registration race: between APC delivery and the sensor's register
//     call, the host process itself could grab the challenge nonce and
//     register first. Worst case is degraded telemetry for that one
//     process (kernel callbacks remain ground truth); kernel callbacks
//     cannot be affected by it.

#include "pch.h"

enum class InjectionState : LONG {
	PendingThread = 0,  // process created, nonce minted, no thread yet
	PendingNtdll = 1,   // thread seen, ntdll base not seen yet
	Ready = 2,          // thread + ntdll base present, injection pending
	Injected = 3,       // APC queued
	Registered = 4,     // sensor echoed the nonce
	Failed = 5,         // thread gone / allocation / queue failure
};

struct InjectionEntry {
	LIST_ENTRY Link;
	ULONG Pid;
	ULONG64 CreateTime;      // identity pairing
	ULONG64 Nonce;           // per-injection secret, echoed at registration
	PETHREAD InitialThread;  // referenced while the entry lives
	PVOID NtdllBase;         // ntdll base in THIS process
	InjectionState State;

	// Sensor ring (D3 slice 2): one section per sensor, kernel-mapped for
	// drain, duplicated into the target at challenge time.
	HANDLE RingSection;
	PVOID RingKernelVa;
	ULONG64 RingDrainIndex;  // kernel-private cursor (never shared)
	ULONG SensorVersion;
};

// Engine API (implemented in Injection.cpp, state in Globals).
void InjectionInit();
void InjectionCleanup();
// Replaces the policy: enabled flag, sensor DLL path (verbatim to
// LdrLoadDll — NT form recommended), extra exclusion names (NUL-terminated
// wide blob, same form as the file-watch lists). Returns false on
// allocation failure (the previous policy stays).
bool InjectionSetPolicy(_In_ bool enabled, _In_ PCUNICODE_STRING dllPath,
	_In_opt_ PCUNICODE_STRING extraExclusions);
void InjectionOnProcessCreate(_In_ ULONG pid, _In_ ULONG64 createTime,
	_In_opt_ PCUNICODE_STRING imageFileName);
void InjectionOnFirstThread(_In_ ULONG pid, _In_ PETHREAD thread);
void InjectionOnImageLoad(_In_ ULONG pid, _In_ PVOID base, _In_ PCUNICODE_STRING fullImageName);
void InjectionOnProcessExit(_In_ ULONG pid);
// Ledger-gated sensor handshake: the challenge is answered only for a pid
// the engine injected and only before registration (one-shot).
struct SensorChallenge;
bool InjectionSensorChallenge(_In_ ULONG pid, _In_ HANDLE callerProcess, _Inout_ SensorChallenge* challenge);
bool InjectionSensorRegister(_In_ ULONG pid, _In_ ULONG64 nonce, _In_ ULONG sensorVersion);
// Drains every registered sensor ring into the file (flood) queue. Called
// from the drain IOCTL; capped per call.
void InjectionDrainRings();
// Implemented in secoutfall.cpp (owns the record allocator + queues): the
// drain promotes a validated ring slot into a BehaviorCall wire record.
void InjectionEmitBehaviorCall(_In_ ULONG pid, _In_ ULONG64 createTime,
	_In_ ULONG threadId, _In_ ULONG api, _In_ ULONG64 arg0, _In_ ULONG64 arg1,
	_In_ ULONG64 arg2, _In_ ULONG64 arg3);
