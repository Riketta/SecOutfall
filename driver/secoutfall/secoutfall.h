#pragma once

#define DRIVER_PREFIX "secoutfall: "
#define DRIVER_TAG 'sfal'

#include "FastMutex.h"
#include "Identity.h"
#include "Queue.h"

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
	// Heap-built in DriverEntry: a global IdentityTable would carry the
	// FastMutex constructor into static init (LNK4210 — drivers have no CRT).
	IdentityTable* Identities;
};
