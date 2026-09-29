#pragma once

class FastMutex {
public:
	FastMutex();

	FastMutex(const FastMutex&) = delete;
	FastMutex& operator=(const FastMutex&) = delete;

	void Lock();
	void Unlock();

private:
	FAST_MUTEX _mutex;
};
