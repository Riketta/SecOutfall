#pragma once

// File-telemetry policy, pushed from user mode via SET_FILE_WATCH. Stays OFF
// until enabled: a driver that observes nothing cannot flood anything, and
// the enabled state plus the extension list swap atomically under one lock.
//
// Matching is a case-insensitive SUFFIX compare of the normalized path
// against each configured extension (with the dot, e.g. L".exe"). An empty
// list means ALL files — the dumper's lab mode; the agent will configure a
// real list. Heap-built in DriverEntry: a global would carry the FastMutex
// constructor into static init (LNK4210 — drivers have no CRT).

#include "AutoLock.h"
#include "FastMutex.h"

class FileWatch {
public:
	static const ULONG MaxExtensions = 64;
	static const ULONG MaxBlobBytes = 4096;

	void Init() {
		_enabled = false;
		_extensions = nullptr;
		_count = 0;
		_blob = nullptr;
		_blobBytes = 0;
	}

	bool Enabled() {
		AutoLock<FastMutex> locker(_lock);
		return _enabled;
	}

	// Replacement is built FIRST (allocation failure keeps the old policy),
	// then swapped under the lock. Takes ownership of the passed allocations.
	bool Apply(_In_ bool enabled, _In_opt_ PUNICODE_STRING* extensions, _In_ ULONG count,
		_In_opt_ PWCHAR blob, _In_ ULONG blobBytes) {
		AutoLock<FastMutex> locker(_lock);
		FreeLocked();
		_enabled = enabled;
		_extensions = extensions;
		_count = count;
		_blob = blob;
		_blobBytes = blobBytes;
		return true;
	}

	// Suffix match under the lock.
	bool Matches(_In_ PCUNICODE_STRING path) {
		AutoLock<FastMutex> locker(_lock);
		if (!_enabled)
			return false;
		if (_count == 0)
			return true; // enabled with no list: everything
		for (ULONG i = 0; i < _count; ++i) {
			auto ext = _extensions[i];
			if (path->Length < ext->Length)
				continue;
			UNICODE_STRING tail;
			tail.Buffer = path->Buffer + (path->Length - ext->Length) / sizeof(WCHAR);
			tail.Length = ext->Length;
			tail.MaximumLength = ext->Length;
			if (::RtlEqualUnicodeString(&tail, ext, TRUE))
				return true;
		}
		return false;
	}

private:
	// Lock held.
	void FreeLocked() {
		if (_extensions) {
			for (ULONG i = 0; i < _count; ++i) {
				if (_extensions[i])
					ExFreePool(_extensions[i]);
			}
			ExFreePool(_extensions);
			_extensions = nullptr;
		}
		if (_blob) {
			ExFreePool(_blob);
			_blob = nullptr;
		}
		_count = 0;
		_blobBytes = 0;
	}

	FastMutex _lock;
	bool _enabled;
	PUNICODE_STRING* _extensions;
	ULONG _count;
	PWCHAR _blob;
	ULONG _blobBytes;
};
