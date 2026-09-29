// secoutfall console dumper: opens the driver's control device and prints
// drained events. D0 tool — the agent's DriverEventSourceAdapter (D5)
// replaces it on the consumption side.

#include <windows.h>
#include <cstdio>
#include <string>

#include "..\secoutfall\secoutfallCommon.h"

enum class ConsoleColor : WORD {
	DarkGreen = 2,
	DarkRed = 4,
	Cyan = 11,
	Green = 10,
	Red = 12,
	Gray = 7,
	White = 15,
};

void SetColor(ConsoleColor color) {
	auto output = ::GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	if (::GetConsoleScreenBufferInfo(output, &info))
		::SetConsoleTextAttribute(output, (info.wAttributes & 0xF0) | static_cast<WORD>(color));
}

int Error(const char* msg) {
	printf("%s (error %lu)\n", msg, ::GetLastError());
	return 1;
}

void DisplayTime(const LARGE_INTEGER& time) {
	FILETIME ft;
	ft.dwLowDateTime = time.LowPart;
	ft.dwHighDateTime = time.HighPart;
	SYSTEMTIME st;
	::FileTimeToSystemTime(&ft, &st);
	printf("%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayData(const BYTE* buffer, DWORD size) {
	while (size >= sizeof(ItemHeader)) {
		auto header = reinterpret_cast<const ItemHeader*>(buffer);
		if (header->Size < static_cast<short>(sizeof(ItemHeader)) || header->Size > static_cast<short>(size)) {
			printf("malformed item size %d — stopping parse\n", header->Size);
			return;
		}

		DisplayTime(header->Time);
		printf(": ");

		switch (header->Type) {
			case ItemType::ProcessCreated:
			{
				SetColor(ConsoleColor::Green);
				auto item = reinterpret_cast<const ProcessCreateInfo*>(header);
				auto commandLine = std::wstring(
					reinterpret_cast<const WCHAR*>(buffer + item->CommandLineOffset), item->CommandLineLength);
				printf("process %lu created (parent %lu): %.*ls\n",
					item->ProcessId, item->ParentProcessId,
					static_cast<int>(commandLine.size()), commandLine.c_str());
				break;
			}

			case ItemType::ProcessExited:
			{
				SetColor(ConsoleColor::Red);
				auto item = reinterpret_cast<const ProcessExitInfo*>(header);
				printf("process %lu exited\n", item->ProcessId);
				break;
			}

			case ItemType::ThreadCreated:
			case ItemType::ThreadExited:
			{
				bool created = header->Type == ItemType::ThreadCreated;
				SetColor(created ? ConsoleColor::DarkGreen : ConsoleColor::DarkRed);
				auto item = reinterpret_cast<const ThreadCreateExitInfo*>(header);
				printf("thread %lu (pid %lu) %s\n",
					item->ThreadId, item->ProcessId, created ? "created" : "exited");
				break;
			}

			case ItemType::RegistrySetValue:
			{
				SetColor(ConsoleColor::Cyan);
				auto item = reinterpret_cast<const RegistrySetValueInfo*>(header);
				printf("registry write (pid %lu) %ls\\%ls type %lu size %lu\n",
					item->ProcessId, item->KeyName, item->ValueName, item->DataType, item->DataSize);
				break;
			}

			default:
				printf("unknown item type %d\n", header->Type);
				break;
		}

		size -= static_cast<DWORD>(header->Size);
		buffer += header->Size;
	}
}

int main() {
	SetColor(ConsoleColor::Gray);
	auto device = ::CreateFileW(L"\\\\.\\" SECOUTFALL_NAME, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (device == INVALID_HANDLE_VALUE)
		return Error("failed to open \\\\.\\secoutfall — is the driver loaded? (sc query secoutfall)");

	BYTE buffer[1 << 16];
	DWORD size = 0;
	while (true) {
		if (!::DeviceIoControl(device, IOCTL_SECOUTFALL_GET_DATA, nullptr, 0UL, buffer,
			static_cast<DWORD>(sizeof(buffer)), &size, nullptr))
			return Error("DeviceIoControl failed");
		if (size > 0)
			DisplayData(buffer, size);
		::Sleep(100);
	}
}
