#pragma once

void* __cdecl operator new(size_t size, POOL_TYPE type);
void __cdecl operator delete(void* p, size_t);
