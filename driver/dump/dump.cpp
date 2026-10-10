// secoutfall console dumper: opens the driver's control device, prints
// drained wire-v2 events and the loss-counter stats. D1 tool — the agent's
// DriverEventSourceAdapter (D5) replaces it on the consumption side.

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

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

// The drained stream is hostile input (any SYSTEM/Admin process can drain the
// device too): every offset and length from the record is validated against
// the checked record size before a single byte is read.
bool RangeOk(DWORD recordSize, USHORT offset, USHORT bytes) {
	return bytes % 2 == 0
		&& offset >= sizeof(RecordHeader)
		&& static_cast<ULONG>(offset) + bytes <= recordSize;
}

std::wstring ReadWstr(const BYTE* record, USHORT offset, USHORT bytes) {
	if (!RangeOk(0, offset, bytes))
		return L"<out of range>";
	return std::wstring(reinterpret_cast<const WCHAR*>(record + offset), bytes / sizeof(WCHAR));
}

std::wstring TruncSuffix(UCHAR flags, UCHAR bit, const WCHAR* what) {
	return (flags & bit) ? std::wstring(L" [") + what + L" TRUNCATED]" : L"";
}

void DisplayTime(const LARGE_INTEGER& time) {
	FILETIME ft;
	ft.dwLowDateTime = time.LowPart;
	ft.dwHighDateTime = time.HighPart;
	SYSTEMTIME st;
	::FileTimeToSystemTime(&ft, &st);
	printf("%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayStats(const DriverStats& stats) {
	SetColor(ConsoleColor::White);
	printf("stats: queue %lu/%lu, seq %llu | lost: overwritten %llu, alloc-fail %llu, oversized %llu, identity-miss %llu\n",
		stats.QueueDepth, stats.QueueCapacity,
		static_cast<unsigned long long>(stats.Sequence),
		static_cast<unsigned long long>(stats.QueueOverwritten),
		static_cast<unsigned long long>(stats.AllocFailures),
		static_cast<unsigned long long>(stats.OversizedSkipped),
		static_cast<unsigned long long>(stats.IdentityMisses));
}

void DisplayData(const BYTE* buffer, DWORD size) {
	while (size >= sizeof(RecordHeader)) {
		auto header = reinterpret_cast<const RecordHeader*>(buffer);
		if (header->Magic != SECOUTFALL_WIRE_MAGIC || header->Version != SECOUTFALL_WIRE_VERSION) {
			printf("unknown wire magic/version %04X/%u — stopping parse\n", header->Magic, header->Version);
			return;
		}
		if (header->HeaderSize != sizeof(RecordHeader)) {
			printf("unexpected header size %u — stopping parse\n", header->HeaderSize);
			return;
		}
		if (header->Size < sizeof(RecordHeader) || header->Size > size) {
			printf("malformed record size %lu — stopping parse\n", header->Size);
			return;
		}

		DisplayTime(*reinterpret_cast<const LARGE_INTEGER*>(&header->Time));
		printf(": ");

		switch (static_cast<RecordType>(header->Type)) {
			case ProcessCreated:
			{
				SetColor(ConsoleColor::Green);
				if (header->Size < ProcessCreatedFixed) {
					printf("short ProcessCreated record\n");
					return;
				}
				auto record = reinterpret_cast<const ProcessCreatedRecord*>(buffer);
				auto cmd = record->CommandLineBytes > 0
					? ReadWstr(buffer, record->CommandLineOffset, record->CommandLineBytes)
					: std::wstring(L"<none>");
				printf("process %lu created (parent %lu, id %llu): %ws%ws\n",
					header->ProcessId, record->ParentProcessId,
					static_cast<unsigned long long>(header->ProcessCreateTime), cmd.c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_CMDLINE, L"cmdline").c_str());
				break;
			}

			case ProcessExited:
			{
				SetColor(ConsoleColor::DarkGreen);
				printf("process %lu exited (id %llu)\n",
					header->ProcessId, static_cast<unsigned long long>(header->ProcessCreateTime));
				break;
			}

			case ThreadCreated:
			case ThreadExited:
			{
				SetColor(ConsoleColor::Gray);
				if (header->Size < ThreadFixed) {
					printf("short thread record\n");
					return;
				}
				auto record = reinterpret_cast<const ThreadRecord*>(buffer);
				printf("thread %lu %hs in process %lu\n",
					record->ThreadId,
					header->Type == ThreadCreated ? "created" : "exited",
					header->ProcessId);
				break;
			}

			case ImageLoaded:
			{
				SetColor(ConsoleColor::White);
				if (header->Size < ImageLoadedFixed) {
					printf("short image record\n");
					return;
				}
				auto record = reinterpret_cast<const ImageLoadedRecord*>(buffer);
				auto name = ReadWstr(buffer, record->NameOffset, record->NameBytes);
				printf("image %ws loaded in process %lu (base %llx, %lu bytes)%ws\n",
					name.c_str(), header->ProcessId,
					static_cast<unsigned long long>(record->ImageBase), record->ImageSize,
					TruncSuffix(header->TruncFlags, TRUNC_IMAGE_NAME, L"name").c_str());
				break;
			}

			case RegistryKeyCreated:
			case RegistryKeyDeleted:
			{
				SetColor(ConsoleColor::Cyan);
				if (header->Size < RegistryKeyFixed) {
					printf("short registry-key record\n");
					return;
				}
				auto record = reinterpret_cast<const RegistryKeyRecord*>(buffer);
				auto path = ReadWstr(buffer, record->PathOffset, record->PathBytes);
				printf("registry key %hs: %ws (process %lu)%ws\n",
					header->Type == RegistryKeyCreated ? "created" : "deleted",
					path.c_str(), header->ProcessId,
					TruncSuffix(header->TruncFlags, TRUNC_KEY_PATH, L"path").c_str());
				break;
			}

			case RegistrySetValue:
			{
				SetColor(ConsoleColor::Cyan);
				if (header->Size < RegistrySetValueFixed) {
					printf("short registry set-value record\n");
					return;
				}
				auto record = reinterpret_cast<const RegistrySetValueRecord*>(buffer);
				auto key = ReadWstr(buffer, record->KeyPathOffset, record->KeyPathBytes);
				auto value = ReadWstr(buffer, record->ValueNameOffset, record->ValueNameBytes);
				printf("registry write (process %lu): %ws\\%ws type %lu size %lu%ws%ws\n",
					header->ProcessId, key.c_str(), value.c_str(),
					record->DataType, record->DataBytes,
					TruncSuffix(header->TruncFlags, TRUNC_KEY_PATH, L"key").c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_DATA, L"data").c_str());
				break;
			}

			default:
				printf("unknown record type %u (size %lu) — skipping (forward compat)\n",
					header->Type, header->Size);
				break;
		}

		size -= header->Size;
		buffer += header->Size;
	}

	if (size > 0)
		printf("%lu trailing bytes — stopping parse\n", size);
}

int main() {
	SetColor(ConsoleColor::Gray);
	auto device = ::CreateFileW(L"\\\\.\\" SECOUTFALL_NAME, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (device == INVALID_HANDLE_VALUE)
		return Error("failed to open \\\\.\\secoutfall — is the driver loaded? (sc query secoutfall)");

	std::vector<BYTE> buffer(1u << 20);
	DWORD size = 0;
	auto first = true;
	while (true) {
		// Stats are loss accounting, not telemetry: fetch per iteration, print
		// once at start and whenever any counter moves.
		static DriverStats last {};
		if (::DeviceIoControl(device, IOCTL_SECOUTFALL_GET_STATS, nullptr, 0UL,
			&last, sizeof(last), &size, nullptr) && size == sizeof(last))
			DisplayStats(last);

		if (!::DeviceIoControl(device, IOCTL_SECOUTFALL_GET_DATA, nullptr, 0UL,
			buffer.data(), static_cast<DWORD>(buffer.size()), &size, nullptr))
			return Error("DeviceIoControl failed");
		if (size > 0)
			DisplayData(buffer.data(), size);
		if (first) {
			printf("draining...\n");
			first = false;
		}
		::Sleep(100);
	}
}
