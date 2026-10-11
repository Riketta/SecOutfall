#include "pch.h"
#include "Memory.h"
#include "secoutfall.h"

// `new (pool)` for the C++-lite object model. The pool argument is HONORED:
// objects whose locks/fields are touched from minifilter post-op callbacks
// (DISPATCH_LEVEL-possible) must be allocated nonpaged — a paged allocation
// there is a documented bugcheck. ExAllocatePool2 fails fast instead of
// raising; it zeroes memory by default (the registry path relies on that for
// NUL-terminated names).
void* __cdecl operator new(size_t size, POOL_TYPE pool) {
	auto flags = (pool == PagedPool) ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;
	return ExAllocatePool2(flags, size, DRIVER_TAG);
}

void __cdecl operator delete(void* p, size_t) {
	ExFreePool(p);
}
