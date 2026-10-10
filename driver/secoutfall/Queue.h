#pragma once
#include "AutoLock.h"

template<typename TLock>
class Queue {
public:
	// `overflowCounter` (optional) counts every drop-oldest eviction — silent
	// loss is doctrine-forbidden, the drain surfaces it via GET_STATS.
	Queue(int maxItems, volatile LONG64* overflowCounter = nullptr) :
		_maxItems(maxItems), _size(0), _overflowCounter(overflowCounter) {
		InitializeListHead(&_head);
	}

	template<typename T>
	void Push(T* entry) {
		AutoLock<TLock> locker(_lock);
		if (_size == _maxItems) {
			//
			// queue too large, remove head (oldest)
			//
			auto item = RemoveHeadList(&_head);
			ExFreePool(CONTAINING_RECORD(item, T, Entry));
			_size--;
			if (_overflowCounter)
				InterlockedIncrement64(_overflowCounter);
		}
		InsertTailList(&_head, &entry->Entry);
		_size++;
	}

	template<typename T>
	T* Pop() {
		AutoLock<TLock> locker(_lock);
		if (_size == 0)
			return nullptr;
		auto entry = RemoveHeadList(&_head);
		_size--;
		return CONTAINING_RECORD(entry, T, Entry);
	}

	//
	// Pop the head item only when its serialized size fits in `available`
	// bytes. Peek + Pop as separate lock acquisitions let two concurrent
	// drains validate one item and pop another (size from X, bytes from Y —
	// a pool over-read and a corrupt record stream). One lock hold makes the
	// check-and-remove atomic; a head that does not fit stays queued.
	//
	template<typename T>
	T* PopIfFits(ULONG available) {
		AutoLock<TLock> locker(_lock);
		if (_size == 0)
			return nullptr;
		auto item = CONTAINING_RECORD(_head.Flink, T, Entry);
		if (static_cast<ULONG>(item->Item.Size) > available)
			return nullptr;
		RemoveHeadList(&_head);
		_size--;
		return item;
	}

	int GetCount() const {
		return _size;
	}

	int GetCapacity() const {
		return _maxItems;
	}

	// Sequence of the head item, or MAX for empty. The merged drain picks the
	// globally smaller sequence across both rate-class queues.
	template<typename T>
	ULONG64 HeadSeq() const {
		AutoLock<TLock> locker(_lock);
		if (_size == 0)
			return MAXULONGLONG;
		auto item = CONTAINING_RECORD(_head.Flink, T, Entry);
		return item->Item.Sequence;
	}

	// Serialized size of the head item, or 0 when empty. The drain uses this
	// to distinguish "head too big for the remaining buffer" (stop, leave it
	// for a bigger batch) from "head bigger than any buffer" (skip + count).
	template<typename T>
	ULONG HeadSize() const {
		AutoLock<TLock> locker(_lock);
		if (_size == 0)
			return 0;
		auto item = CONTAINING_RECORD(_head.Flink, T, Entry);
		return static_cast<ULONG>(item->Item.Size);
	}

	template<typename T>
	T* Peek() const {
		AutoLock<TLock> locker(_lock);
		if (_size == 0)
			return nullptr;
		auto item = _head.Flink;
		return CONTAINING_RECORD(item, T, Entry);
	}

	template<typename T>
	void FreeAll() {
		while (_size > 0)
			ExFreePool(Pop<T>());
	}

private:
	LIST_ENTRY _head;
	int _maxItems, _size;
	mutable TLock _lock;
	volatile LONG64* _overflowCounter;
};
