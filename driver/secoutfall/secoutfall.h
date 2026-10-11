#pragma once

#define DRIVER_PREFIX "secoutfall: "
#define DRIVER_TAG 'sfal'

// Release-live logging: KdPrint compiles out without DBG (checked builds
// only), DbgPrintEx stays active in free builds. ERROR level prints by
// default; install.ps1 raises the IHVDRIVER Debug Print Filter so WARNING
// and INFO show in DebugView/WinDbg too. Use on failure paths and one-shot
// policy announcements ONLY — never per-event: the hot paths report through
// the GET_STATS counters, not strings.
#define SF_LOG_ERROR(...) ::DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX __VA_ARGS__)
#define SF_LOG_WARN(...)  ::DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, DRIVER_PREFIX __VA_ARGS__)
#define SF_LOG_INFO(...)  ::DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX __VA_ARGS__)

#include <fltKernel.h>

#include "FastMutex.h"
#include "FileWatch.h"
#include "Identity.h"
#include "Queue.h"

struct DriverGlobals;

template<typename T>
struct ItemFull {
	LIST_ENTRY Entry;
	T Item;
};

struct Globals {
	Queue<FastMutex>* Items;
	// The 26100 WDK declares CmRegisterCallbackEx/CmUnRegisterCallback/
	// CmCallbackGetKeyObjectIDEx with LARGE_INTEGER cookies (documented as
	// ULONG — the header is authoritative).
	LARGE_INTEGER RegistryCookie;

	// Wire v2 bookkeeping: per-boot sequence, loss counters (surfaced via
	// IOCTL_SECOUTFALL_GET_STATS — silent loss is doctrine-forbidden), and
	// the pid -> creation-time identity table.
	volatile LONG64 NextSequence;
	volatile LONG64 QueueOverwritten;
	volatile LONG64 AllocFailures;
	volatile LONG64 OversizedSkipped;
	volatile LONG64 IdentityMisses;
	IdentityTable* Identities;

	//
	// File/flood class (D2): a second rate-class queue so a ransomware-style
	// write storm cannot evict process evidence. Same drain path — GET_DATA
	// merges both lists by sequence.
	//
	Queue<FastMutex>* Files;
	volatile LONG64 FilesOverwritten;
	volatile LONG64 FileNameQueriesFailed;
	volatile LONG64 NoiseWritesSkipped;

	//
	// Drops class (D2b): captured evidence. Stop-collect on overflow —
	// existing evidence is never evicted, refusal is counted.
	//
	Queue<FastMutex>* Drops;
	volatile LONG64 DropsStopped;
	volatile LONG64 DropsMissedBusy;
	volatile LONG64 DropsLinkFailed;
	volatile LONG64 DropsCopyFailed;
	volatile LONG64 SensorEventsDrained; // ring slots promoted to records
	volatile LONG64 SensorEventsDropped; // slots skipped: torn, stale or garbage
	volatile LONG64 SensorRingsSkipped;  // registered rings beyond a drain snapshot cap
	// Drop extension matcher + target directory (heap-built: FastMutex).
	FileWatch* DropWatch;
	DropTarget* Target;
	volatile LONG64 DropCounter; // stored-name generator, per boot

	//
	// D3 injection engine (all heap-built: FastMutex/ctor traps).
	//
	bool InjectionEnabled;
	UNICODE_STRING SensorDllPath;   // heap buffer, verbatim to LdrLoadDll
	FileWatch* InjectionBlocklist;  // compiled defaults, always on
	FileWatch* InjectionExtraBlocklist; // policy extras, usually empty
	LIST_ENTRY InjectionLedger;
	FastMutex* InjectionLedgerLock;
	ULONG InjectionLedgerCount;
	ULONG LdrLoadDllRva;            // resolved from the first ntdll load
	bool LdrLoadDllRvaResolved;
	volatile LONG64 InjectionsQueued;
	volatile LONG64 InjectionsFailed;
	volatile LONG64 InjectionNonceCounter; // nonce ingredient (never surfaced)
	volatile LONG64 SensorsRegistered;
	volatile LONG64 SensorsRejected;
	volatile LONG64 ProtectionsStripped; // handle-open attempts stripped
	volatile LONG64 ProtectionTrusted;   // attempts allowed (trusted caller)
	PVOID ObRegistration;                // ObCallbacks handle (D4)

	// Minifilter registration handle (nullptr until registered).
	PFLT_FILTER Filter;

	// File-telemetry policy (heap-built: see FileWatch.h).
	FileWatch* Watch;
};

// The single engine state; defined in secoutfall.cpp.
extern Globals g_Data;
