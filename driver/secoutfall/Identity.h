#pragma once

// Maps pid -> driver-witnessed creation time (the system time captured in the
// process-create callback). The pair is the process identity on the wire:
// pid alone is ambiguous across recycling (the same bug class the agent's
// scope DB already fixed). Processes that existed before the driver loaded
// have no witnessed time and resolve to 0 — always safe (they are system
// processes, never in scope), never wrong.
//
// Fixed bucket count, capped total entries. On overflow the NEWEST insert is
// refused (not the oldest evicted): lookups for refused pids degrade to
// identity 0, which is honest "unknown", and the refusal is counted as an
// identity miss by the caller. Nonpaged entries: the table is consulted from
// thread/image/registry callbacks whose IRQL guarantees are safest not to
// depend on for paging decisions; 4096 entries * ~32 bytes is a 128 KiB cap.

#include "AutoLock.h"
#include "FastMutex.h"

class IdentityTable {
public:
	static const ULONG BucketCount = 256;
	static const ULONG MaxEntries = 4096;

	void Init() {
		_count = 0;
		for (auto& bucket : _buckets)
			InitializeListHead(&bucket);
	}

	// Returns false when the table is full (caller counts an identity miss).
	bool Insert(_In_ ULONG pid, _In_ ULONG64 createTime) {
		AutoLock<FastMutex> locker(_lock);
		if (_count >= MaxEntries)
			return false;
		if (LookupLocked(pid) != nullptr)
			return true; // pid already tracked (should not happen; keep newest's absence)
		auto entry = (Entry*)::ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Entry), DRIVER_TAG);
		if (entry == nullptr)
			return false;
		entry->Pid = pid;
		entry->CreateTime = createTime;
		InsertTailList(&_buckets[Hash(pid)], &entry->Link);
		_count++;
		return true;
	}

	void Remove(_In_ ULONG pid) {
		AutoLock<FastMutex> locker(_lock);
		if (auto entry = LookupLocked(pid)) {
			RemoveEntryList(&entry->Link);
			ExFreePool(entry);
			_count--;
		}
	}

	// 0 = unknown identity (pre-load process, refused insert, or alloc failure).
	ULONG64 Lookup(_In_ ULONG pid) {
		AutoLock<FastMutex> locker(_lock);
		auto entry = LookupLocked(pid);
		return entry ? entry->CreateTime : 0;
	}

	void Clear() {
		AutoLock<FastMutex> locker(_lock);
		for (auto& bucket : _buckets) {
			while (!IsListEmpty(&bucket)) {
				auto link = RemoveHeadList(&bucket);
				ExFreePool(CONTAINING_RECORD(link, Entry, Link));
			}
		}
		_count = 0;
	}

	ULONG Count() const { return _count; }

private:
	struct Entry {
		LIST_ENTRY Link;
		ULONG Pid;
		ULONG64 CreateTime;
	};

	static ULONG Hash(_In_ ULONG pid) {
		// Knuth multiplicative: cheap, well-distributed for sequential pids.
		return (pid * 2654435761u) % BucketCount;
	}

	// Lock held.
	Entry* LookupLocked(_In_ ULONG pid) {
		for (auto link = _buckets[Hash(pid)].Flink; link != &_buckets[Hash(pid)]; link = link->Flink) {
			auto entry = CONTAINING_RECORD(link, Entry, Link);
			if (entry->Pid == pid)
				return entry;
		}
		return nullptr;
	}

	LIST_ENTRY _buckets[BucketCount];
	FastMutex _lock;
	ULONG _count;
};
