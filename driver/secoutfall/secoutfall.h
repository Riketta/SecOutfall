#pragma once

#define DRIVER_PREFIX "secoutfall: "
#define DRIVER_TAG 'sfal'

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
	volatile LONG64 SensorsRegistered;
	volatile LONG64 SensorsRejected;

	// File telemetry stays OFF until a client (agent/dumper) sends
	// SET_FILE_WATCH — a driver that observes nothing cannot flood anything.
	volatile LONG64 FileWatchEnabled;
	// Configured extension list (each WITH the dot, e.g. L".exe"), nonpaged
	// UNICODE_STRING array; empty array + enabled = ALL files.
	PUNICODE_STRING* Extensions;
	ULONG ExtensionsCount;
	// Scratch buffer backing the extension strings.
	PWCHAR ExtensionsBlob;

	// Minifilter registration handle (nullptr until registered).
	PFLT_FILTER Filter;

	// File-telemetry policy (heap-built: see FileWatch.h).
	FileWatch* Watch;
};

// The single engine state; defined in secoutfall.cpp.
extern Globals g_Data;
