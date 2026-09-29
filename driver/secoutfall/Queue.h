#pragma once
#include "AutoLock.h"

template<typename TLock>
class Queue {
public:
	Queue(int maxItems) : _maxItems(maxItems), _size(0) {
		InitializeListHead(&_head);
	}

	template<typename T>
	void Push(T* entry) {
		AutoLock<TLock> locker(_lock);
		if (_size == _maxItems) {
			//
			// queue too large, remove head
			//
			auto item = RemoveHeadList(&_head);
			ExFreePool(CONTAINING_RECORD(item, T, Entry));
			_size--;
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

	int GetCount() const {
		return _size;
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
};
