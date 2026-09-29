#pragma once

#define DRIVER_PREFIX "secoutfall: "
#define DRIVER_TAG 'sfal'

#include "FastMutex.h"
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
};
