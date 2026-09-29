#include "pch.h"
#include "Memory.h"
#include "secoutfall.h"

// `new (PagedPool)` for the C++-lite object model. ExAllocatePool2 fails
// fast instead of raising; it zeroes memory by default (the registry path
// relies on that for NUL-terminated names).
void* __cdecl operator new(size_t size, POOL_TYPE) {
	return ExAllocatePool2(POOL_FLAG_PAGED, size, DRIVER_TAG);
}

void __cdecl operator delete(void* p, size_t) {
	ExFreePool(p);
}
