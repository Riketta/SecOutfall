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
	// Drop extension matcher + target directory (heap-built: FastMutex).
	FileWatch* DropWatch;
	DropTarget* Target;
	volatile LONG64 DropCounter; // stored-name generator, per boot

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
