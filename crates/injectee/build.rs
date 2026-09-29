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
        // "NtTraceEvent",
    ];

    windows_bindgen::bindgen(args);
}
