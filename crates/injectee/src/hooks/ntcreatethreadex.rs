//! `NtCreateThreadEx` hook: thread creation — cross-process thread creation
//! is the classic injection signature (chain candidate for scoring).
//! Observe-only.

#![allow(clippy::too_many_arguments, clippy::cast_sign_loss, clippy::cast_lossless, clippy::doc_markdown)]

crate::hook! {
    /// Reports thread creation calls, passes them through unchanged.
    in "ntdll.dll"!NtCreateThreadEx as NTCREATETHREADEX_ORIGINAL
    fn ntcreatethreadex_detour(
        thread_handle: *mut core::ffi::c_void,
        desired_access: u32,
        object_attributes: *const core::ffi::c_void,
        process_handle: *mut core::ffi::c_void,
        start_routine: *const core::ffi::c_void,
        argument: *const core::ffi::c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *const core::ffi::c_void,
    ) -> i32 {
        let args = [
            process_handle as u64,
            start_routine as u64,
            u64::from(create_flags),
            desired_access as u64,
        ];
        crate::sensor::emit(crate::sensor::api::NT_CREATE_THREAD_EX, args);
        unsafe {
            NTCREATETHREADEX_ORIGINAL.call(
                thread_handle,
                desired_access,
                object_attributes,
                process_handle,
                start_routine,
                argument,
                create_flags,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list,
            )
        }
    }
}
