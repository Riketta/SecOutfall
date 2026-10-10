fn main() {
    let args = [
        "--sys",
        "--out",
        "src/bindings.rs",
        "--flat",
        "--filter",
        "GetTickCount",
        "Sleep",
        "NtCreateFile",
        "NtWriteFile",
        "NtClose",
        "DeviceIoControl",
        "CreateFileW",
        "CloseHandle",
        "MapViewOfFile",
        "UnmapViewOfFile",
        "GetCurrentThreadId",
    ];

    windows_bindgen::bindgen(args);
}
