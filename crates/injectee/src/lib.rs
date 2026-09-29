pub(crate) mod hooking;
pub(crate) mod hooks;
mod utils;

use std::process::Command;

use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};
use windows::core::{PCSTR, s};

const TITLE: PCSTR = s!("Injectee");

#[allow(non_snake_case, unused_variables)]
#[unsafe(no_mangle)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => detach(),
        _ => (),
    }

    true
}

fn attach() {
    unsafe {
        _ = AllocConsole();

        let pid = GetCurrentProcessId();
        utils::message_box(std::format!("Process: {pid}!\0").as_str());
    };

    let mut command = Command::new("calc");
    command.arg("").arg("");
    let mut handle = command.spawn().unwrap();

    if let Err(err) = hooks::install_all() {
        eprintln!("injection failed: {err}");
        // loop {} // TODO: not good for self-injection test case.
    }
}

fn detach() {
    utils::message_box("Deatching");
}

fn hide_self() {
    todo!()
}

fn force_unload() {
    todo!()
}

#[unsafe(no_mangle)]
pub extern "system" fn some_export() {
    std::hint::black_box(());
}

#[cfg(test)]
mod tests {

    use std::{thread::sleep, time::Duration};

    use crate::hooking::get_module_symbol_address;

    use super::*;
    use anyhow::Result;
    use windows::{
        Win32::{
            Foundation::{ERROR_SUCCESS, GetLastError, SetLastError},
            System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
        },
        core::{PCWSTR, w},
    };

    // TODO: should be macro.
    #[inline]
    fn assert_last_error() {
        let win32_error = unsafe { GetLastError() };
        assert_eq!(win32_error.0, 0);
    }

    #[test]
    #[ignore = "needs the injected DLL's exports; the test executable exports none"]
    fn test_get_proc_address_self() -> Result<()> {
        unsafe { SetLastError(ERROR_SUCCESS) };
        let procedure_cstr = s!("some_export");
        let procedure = "some_export";

        let address_from_raw_call = unsafe {
            let module_handle = GetModuleHandleW(PCWSTR(std::ptr::null()))?;
            assert_ne!(module_handle.0 as usize, 0);
            GetProcAddress(module_handle, procedure_cstr).unwrap() as usize
        };
        assert_last_error();
        let address_from_wrapper = get_module_symbol_address(None, procedure).unwrap();
        assert_last_error();

        assert_ne!(address_from_raw_call, 0);
        assert_eq!(address_from_raw_call, address_from_wrapper);
        println!("{procedure} address: {address_from_raw_call}.");

        Ok(())
    }

    #[test]
    fn test_get_proc_address_kernel() -> Result<()> {
        unsafe { SetLastError(ERROR_SUCCESS) };
        let module_cwstr = w!("kernel32.dll");
        let module = "kernel32.dll";
        let procedure_cstr = s!("lstrlenW");
        let procedure = "lstrlenW";

        let address_from_raw_call = unsafe {
            let module_handle = GetModuleHandleW(module_cwstr)?;
            assert_ne!(module_handle.0 as usize, 0);
            GetProcAddress(module_handle, procedure_cstr).unwrap() as usize
        };
        assert_last_error();
        let address_from_wrapper = get_module_symbol_address(Some(module), procedure).unwrap();
        assert_last_error();

        assert_ne!(address_from_raw_call, 0);
        assert_eq!(address_from_raw_call, address_from_wrapper);
        println!("{procedure} address: {address_from_raw_call}.");

        Ok(())
    }

    #[test]
    fn test_get_proc_address_native() -> Result<()> {
        unsafe { SetLastError(ERROR_SUCCESS) };
        let module_cwstr = w!("ntdll.dll");
        let module = "ntdll.dll";
        let procedure_cstr = s!("RtlNtStatusToDosError");
        let procedure = "RtlNtStatusToDosError";

        let address_from_raw_call = unsafe {
            let module_handle = GetModuleHandleW(module_cwstr)?;
            assert_ne!(module_handle.0 as usize, 0);
            GetProcAddress(module_handle, procedure_cstr).unwrap() as usize
        };
        assert_last_error();
        let address_from_wrapper = get_module_symbol_address(Some(module), procedure).unwrap();
        assert_last_error();

        assert_ne!(address_from_raw_call, 0);
        assert_eq!(address_from_raw_call, address_from_wrapper);
        println!("{procedure} address: {address_from_raw_call}.");

        Ok(())
    }

    #[test]
    #[ignore = "manual check: blocks on a message box and force_unload is unimplemented"]
    fn test_self_injection() -> Result<()> {
        DllMain(
            HINSTANCE(std::ptr::null_mut()),
            DLL_PROCESS_ATTACH,
            std::ptr::null_mut(),
        );

        sleep(Duration::from_millis(10));

        force_unload();

        Ok(())
    }
}
