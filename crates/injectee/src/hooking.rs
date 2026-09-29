//! Minimal hooking framework built on [`retour`] static detours.
//!
//! Define a hook with the [`hook!`] macro, which generates the detour
//! function, a static exposing the original function, and an idempotent
//! `install` function. Then list the generated `install` functions in
//! [`hooks::install_all`](crate::hooks::install_all).

use std::{ffi::CString, iter};

use anyhow::bail;
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    },
    core::{PCSTR, PCWSTR},
};

/// Resolves the address of an exported symbol in `module`, or in any loaded
/// module when `module` is `None`.
pub(crate) fn get_module_symbol_address(
    module: Option<&str>,
    symbol: &str,
) -> anyhow::Result<usize> {
    let module = module.map(|module| {
        module
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>()
    });

    let symbol = CString::new(symbol)?;
    unsafe {
        let handle = GetModuleHandleW(PCWSTR(
            module.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
        ))?;
        Ok(
            GetProcAddress(handle, PCSTR(symbol.as_ptr().cast::<u8>())).ok_or(
                anyhow::Error::msg(format!(
                    "Failed to get {symbol:?} function address: {}.",
                    GetLastError().0
                )),
            )? as usize,
        )
    }
}

/// Installs every hook in `hooks`, collecting all failures before reporting.
pub(crate) fn install_all(hooks: &[fn() -> anyhow::Result<()>]) -> anyhow::Result<()> {
    let mut failures = Vec::new();

    for hook in hooks {
        if let Err(err) = hook() {
            eprintln!("{err:#}");
            failures.push(err);
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "{}/{} hook(s) failed to install.",
            failures.len(),
            hooks.len()
        )
    }
}

/// Defines a hook for an exported function.
///
/// The macro generates three items:
///
/// - the detour function `$name` with `$body`,
/// - a static `$original` calling the original function through
///   [`retour::StaticDetour::call`](::retour::StaticDetour::call),
/// - an idempotent `install` function resolving the symbol in `module` and
///   enabling the detour.
///
/// Keep one hook per module and register the generated `install` function
/// with [`install_all`](crate::hooking::install_all).
///
/// ```ignore
/// crate::hook! {
///     /// Caps every `Sleep` call at one second.
///     in "kernel32.dll"!Sleep as SLEEP_ORIGINAL
///     fn sleep_detour(dwmilliseconds: u32) {
///         println!("Expected sleep time: {dwmilliseconds}.");
///         unsafe { SLEEP_ORIGINAL.call(1000) }
///     }
/// }
/// ```
#[macro_export]
macro_rules! hook {
    (
        $(#[$meta:meta])*
        in $module:literal!$symbol:ident as $original:ident
        fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?
        $body:block
    ) => {
        $(#[$meta])*
        fn $name($($arg: $ty),*) $(-> $ret)? $body

        ::retour::static_detour! {
            static $original: unsafe extern "system" fn($($ty),*) $(-> $ret)?;
        }

        /// Installs the hook, or does nothing when it is already active.
        pub(crate) fn install() -> anyhow::Result<()> {
            if $original.is_enabled() {
                return Ok(());
            }

            println!("Hooking {}!{}.", $module, stringify!($symbol));

            unsafe {
                let address = $crate::hooking::get_module_symbol_address(
                    Some($module),
                    stringify!($symbol),
                )?;
                let target: unsafe extern "system" fn($($ty),*) $(-> $ret)? =
                    core::mem::transmute(address);
                $original.initialize(target, $name)?.enable()?;
            }

            Ok(())
        }
    };
}

#[cfg(test)]
mod tests {
    use super::install_all;

    #[test]
    fn install_all_succeeds_without_hooks() {
        install_all(&[]).unwrap();
    }

    #[test]
    fn install_all_collects_failures() {
        fn failing() -> anyhow::Result<()> {
            anyhow::bail!("failing hook")
        }

        let error = install_all(&[failing]).expect_err("expected failure");
        assert_eq!(error.to_string(), "1/1 hook(s) failed to install.");
    }
}
