use crate::types::{ExportInfo, HookError, ModuleInfo};
use core::ffi::{c_char, c_void};
use libc::{dladdr, dlsym, Dl_info, RTLD_DEFAULT};
use mach2::kern_return::KERN_SUCCESS;
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_protect;
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};
use std::sync::{Mutex, OnceLock};

mod macho {
    // Minimal Mach-O definitions to support in-memory symbol enumeration.

    pub const MH_MAGIC_64: u32 = 0xfeedfacf;
    pub const LC_SEGMENT_64: u32 = 0x19;
    pub const LC_SYMTAB: u32 = 0x2;
    pub const LC_DYSYMTAB: u32 = 0xb;

    pub const N_EXT: u8 = 0x01;

    pub const SECTION_TYPE: u32 = 0x000000ff;
    pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x00000006;
    pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x00000007;

    pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
    pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct mach_header_64 {
        pub magic: u32,
        pub cputype: i32,
        pub cpusubtype: i32,
        pub filetype: u32,
        pub ncmds: u32,
        pub sizeofcmds: u32,
        pub flags: u32,
        pub reserved: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct load_command {
        pub cmd: u32,
        pub cmdsize: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct segment_command_64 {
        pub cmd: u32,
        pub cmdsize: u32,
        pub segname: [u8; 16],
        pub vmaddr: u64,
        pub vmsize: u64,
        pub fileoff: u64,
        pub filesize: u64,
        pub maxprot: i32,
        pub initprot: i32,
        pub nsects: u32,
        pub flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct section_64 {
        pub sectname: [u8; 16],
        pub segname: [u8; 16],
        pub addr: u64,
        pub size: u64,
        pub offset: u32,
        pub align: u32,
        pub reloff: u32,
        pub nreloc: u32,
        pub flags: u32,
        pub reserved1: u32,
        pub reserved2: u32,
        pub reserved3: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct symtab_command {
        pub cmd: u32,
        pub cmdsize: u32,
        pub symoff: u32,
        pub nsyms: u32,
        pub stroff: u32,
        pub strsize: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct dysymtab_command {
        pub cmd: u32,
        pub cmdsize: u32,
        pub ilocalsym: u32,
        pub nlocalsym: u32,
        pub iextdefsym: u32,
        pub nextdefsym: u32,
        pub iundefsym: u32,
        pub nundefsym: u32,
        pub tocoff: u32,
        pub ntoc: u32,
        pub modtaboff: u32,
        pub nmodtab: u32,
        pub extrefsymoff: u32,
        pub nextrefsyms: u32,
        pub indirectsymoff: u32,
        pub nindirectsyms: u32,
        pub extreloff: u32,
        pub nextrel: u32,
        pub locreloff: u32,
        pub nlocrel: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union n_un {
        pub n_strx: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct nlist_64 {
        pub n_un: n_un,
        pub n_type: u8,
        pub n_sect: u8,
        pub n_desc: u16,
        pub n_value: u64,
    }
}

use macho::{
    dysymtab_command, load_command, mach_header_64, nlist_64, section_64, segment_command_64,
    symtab_command, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, LC_DYSYMTAB, LC_SEGMENT_64,
    LC_SYMTAB, MH_MAGIC_64, N_EXT, S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS,
    SECTION_TYPE,
};

extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const mach_header_64;
    fn _dyld_get_image_name(index: u32) -> *const c_char;
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
    fn _dyld_register_func_for_add_image(func: extern "C" fn(*const mach_header_64, isize));
}

#[derive(Clone)]
struct Rebinding {
    want: Vec<u8>,
    replacement: usize,
}

static REBINDINGS: OnceLock<Mutex<Vec<Rebinding>>> = OnceLock::new();
static REBINDINGS_REGISTERED: OnceLock<()> = OnceLock::new();

fn rebindings() -> &'static Mutex<Vec<Rebinding>> {
    REBINDINGS.get_or_init(|| Mutex::new(Vec::new()))
}

fn ensure_rebinding_callback_registered() {
    REBINDINGS_REGISTERED.get_or_init(|| unsafe {
        _dyld_register_func_for_add_image(on_dyld_add_image);
    });
}

extern "C" fn on_dyld_add_image(header: *const mach_header_64, slide: isize) {
    if header.is_null() {
        return;
    }
    unsafe {
        if (*header).magic != MH_MAGIC_64 {
            return;
        }
    }

    // Clone the list to avoid holding the lock while patching images.
    let bindings = {
        let guard = rebindings().lock().unwrap();
        guard.clone()
    };

    unsafe {
        for b in bindings {
            let _ = rebind_symbol_in_image(header, slide, &b.want, b.replacement, None);
        }
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn cstr_from_fixed_bytes(bytes: &[u8; 16]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

unsafe fn load_commands(header: *const mach_header_64) -> (*const load_command, u32) {
    let cmds = (header as *const u8).add(core::mem::size_of::<mach_header_64>()) as *const load_command;
    (cmds, (*header).ncmds)
}

unsafe fn for_each_segment_64(
    header: *const mach_header_64,
    mut f: impl FnMut(&segment_command_64),
) {
    let (mut cmd, ncmds) = load_commands(header);
    for _ in 0..ncmds {
        if (*cmd).cmd == LC_SEGMENT_64 {
            let seg = &*(cmd as *const segment_command_64);
            f(seg);
        }
        cmd = (cmd as *const u8).add((*cmd).cmdsize as usize) as *const load_command;
    }
}

unsafe fn for_each_section_64(header: *const mach_header_64, mut f: impl FnMut(&section_64)) {
    let (mut cmd, ncmds) = load_commands(header);
    for _ in 0..ncmds {
        if (*cmd).cmd == LC_SEGMENT_64 {
            let seg = &*(cmd as *const segment_command_64);
            let mut sec = (seg as *const segment_command_64).add(1) as *const section_64;
            for _ in 0..seg.nsects {
                f(&*sec);
                sec = sec.add(1);
            }
        }
        cmd = (cmd as *const u8).add((*cmd).cmdsize as usize) as *const load_command;
    }
}

unsafe fn find_symtab(header: *const mach_header_64) -> Option<&'static symtab_command> {
    let (mut cmd, ncmds) = load_commands(header);
    for _ in 0..ncmds {
        if (*cmd).cmd == LC_SYMTAB {
            return Some(&*(cmd as *const symtab_command));
        }
        cmd = (cmd as *const u8).add((*cmd).cmdsize as usize) as *const load_command;
    }
    None
}

unsafe fn find_dysymtab(header: *const mach_header_64) -> Option<&'static dysymtab_command> {
    let (mut cmd, ncmds) = load_commands(header);
    for _ in 0..ncmds {
        if (*cmd).cmd == LC_DYSYMTAB {
            return Some(&*(cmd as *const dysymtab_command));
        }
        cmd = (cmd as *const u8).add((*cmd).cmdsize as usize) as *const load_command;
    }
    None
}

unsafe fn fileoff_to_ptr(
    header: *const mach_header_64,
    slide: isize,
    fileoff: u64,
) -> Option<*const u8> {
    let mut out: Option<*const u8> = None;
    for_each_segment_64(header, |seg| {
        if out.is_some() {
            return;
        }
        let start = seg.fileoff;
        let end = seg.fileoff.saturating_add(seg.filesize);
        if fileoff >= start && fileoff < end {
            let delta = fileoff - start;
            let vmaddr = (seg.vmaddr as i128) + (slide as i128) + (delta as i128);
            out = Some(vmaddr as u64 as *const u8);
        }
    });
    out
}

unsafe fn module_range(header: *const mach_header_64, slide: isize) -> Option<(usize, usize)> {
    let mut min: Option<u64> = None;
    let mut max: u64 = 0;
    for_each_segment_64(header, |seg| {
        if seg.vmsize == 0 {
            return;
        }
        let start = (seg.vmaddr as i128 + slide as i128) as u64;
        let end = start.saturating_add(seg.vmsize);
        min = Some(min.map(|m| m.min(start)).unwrap_or(start));
        max = max.max(end);
    });
    min.map(|m| (m as usize, (max - m) as usize))
}

pub fn enumerate_modules() -> Vec<ModuleInfo> {
    let count = unsafe { _dyld_image_count() };
    let mut out = Vec::with_capacity(count as usize);

    for i in 0..count {
        unsafe {
            let header = _dyld_get_image_header(i);
            if header.is_null() {
                continue;
            }
            if (*header).magic != MH_MAGIC_64 {
                continue;
            }

            let slide = _dyld_get_image_vmaddr_slide(i);
            let name_ptr = _dyld_get_image_name(i);
            let path = if name_ptr.is_null() {
                String::new()
            } else {
                // Safety: dyld returns NUL-terminated path string.
                let cstr = core::ffi::CStr::from_ptr(name_ptr);
                cstr.to_string_lossy().into_owned()
            };

            let (base, size) = module_range(header, slide).unwrap_or((header as usize, 0));
            let name = if path.is_empty() {
                format!("image_{i}")
            } else {
                basename(&path).to_string()
            };

            out.push(ModuleInfo {
                name,
                path,
                base_address: base,
                size,
            });
        }
    }

    out
}

pub fn find_module_by_name(name: &str) -> Option<ModuleInfo> {
    enumerate_modules().into_iter().find(|m| m.name == name)
}

pub fn find_global_export_by_name(symbol: &str) -> Result<usize, HookError> {
    let cstr = std::ffi::CString::new(symbol).map_err(|_| HookError::WrongSignature)?;
    unsafe {
        let mut p = dlsym(RTLD_DEFAULT, cstr.as_ptr());
        if !p.is_null() {
            return Ok(p as usize);
        }

        // Compatibility with callers that pass Mach-O `nlist`-style names (leading underscore).
        if let Some(stripped) = symbol.strip_prefix('_') {
            if let Ok(alt) = std::ffi::CString::new(stripped) {
                p = dlsym(RTLD_DEFAULT, alt.as_ptr());
            }
        } else {
            let mut buf = String::with_capacity(symbol.len() + 1);
            buf.push('_');
            buf.push_str(symbol);
            if let Ok(alt) = std::ffi::CString::new(buf) {
                p = dlsym(RTLD_DEFAULT, alt.as_ptr());
            }
        }

        if p.is_null() {
            Err(HookError::WrongSignature)
        } else {
            Ok(p as usize)
        }
    }
}

pub fn find_export_by_name(module_name: &str, symbol: &str) -> Result<usize, HookError> {
    let exports = enumerate_exports(module_name)?;
    for e in exports {
        if e.name == symbol {
            return Ok(e.address);
        }
    }
    Err(HookError::WrongSignature)
}

pub fn enumerate_exports(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    // In Mach-O, "exports" are generally global, externally visible symbols.
    // We approximate this by returning `N_EXT` symbols with non-zero values.
    enumerate_symbols_internal(module_name, true, true)
}

pub fn enumerate_symbols(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    // Strip one leading underscore (Mach-O prefix):
    // `(s[0] == '_') ? s + 1 : s`.
    // This correctly handles C++ mangled names like `__ZN...` → `_ZN...`.
    enumerate_symbols_internal(module_name, false, true)
}

fn enumerate_symbols_internal(
    module_name: &str,
    only_external: bool,
    strip_leading_underscore: bool,
) -> Result<Vec<ExportInfo>, HookError> {
    let module = find_module_by_name(module_name).ok_or(HookError::WrongSignature)?;
    let count = unsafe { _dyld_image_count() };

    // Re-find by name to get the dyld header/slide; module.path may not be unique.
    for i in 0..count {
        unsafe {
            let header = _dyld_get_image_header(i);
            if header.is_null() || (*header).magic != MH_MAGIC_64 {
                continue;
            }
            let name_ptr = _dyld_get_image_name(i);
            let path = if name_ptr.is_null() {
                String::new()
            } else {
                core::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            };
            if basename(&path) != module.name {
                continue;
            }

            let slide = _dyld_get_image_vmaddr_slide(i);
            let symtab = find_symtab(header).ok_or(HookError::WrongSignature)?;

            let sym_ptr = fileoff_to_ptr(header, slide, symtab.symoff as u64)
                .ok_or(HookError::WrongSignature)? as *const nlist_64;
            let str_ptr = fileoff_to_ptr(header, slide, symtab.stroff as u64)
                .ok_or(HookError::WrongSignature)?;

            let mut out = Vec::new();
            for idx in 0..symtab.nsyms {
                let sym = &*sym_ptr.add(idx as usize);
                if sym.n_value == 0 {
                    continue;
                }
                if sym.n_un.n_strx == 0 {
                    continue;
                }
                let is_ext = (sym.n_type & N_EXT) != 0;
                if only_external && !is_ext {
                    continue;
                }

                let name_p = str_ptr.add(sym.n_un.n_strx as usize) as *const c_char;
                if name_p.is_null() {
                    continue;
                }
                let raw = core::ffi::CStr::from_ptr(name_p).to_string_lossy();
                let name = if strip_leading_underscore {
                    raw.strip_prefix('_').unwrap_or(&raw).to_string()
                } else {
                    raw.into_owned()
                };
                out.push(ExportInfo {
                    name,
                    address: (sym.n_value as i128 + slide as i128) as usize,
                });
            }
            return Ok(out);
        }
    }

    Err(HookError::WrongSignature)
}

/// Rebind imported symbol pointers (fishhook-style) in all currently loaded images.
///
/// This is a fallback for hardened / shared-cache code pages where inline patching fails.
/// Returns a list of patched locations and their original values, which can be used to restore.
unsafe fn rebind_symbol_in_image(
    header: *const mach_header_64,
    slide: isize,
    want: &[u8],
    replacement: usize,
    mut patched: Option<&mut Vec<(usize, usize)>>,
) -> Result<(), HookError> {
    let Some(symtab) = find_symtab(header) else { return Ok(()) };
    let Some(dysymtab) = find_dysymtab(header) else { return Ok(()) };

    let Some(symtab_ptr) = fileoff_to_ptr(header, slide, symtab.symoff as u64) else { return Ok(()) };
    let Some(strtab_ptr) = fileoff_to_ptr(header, slide, symtab.stroff as u64) else { return Ok(()) };
    let Some(indirect_ptr) = fileoff_to_ptr(header, slide, dysymtab.indirectsymoff as u64) else { return Ok(()) };

    let symbols = symtab_ptr as *const nlist_64;
    let strings = strtab_ptr;
    let indirect = indirect_ptr as *const u32;

    let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;

    for_each_section_64(header, |sect| {
        let sec_type = sect.flags & SECTION_TYPE;
        if sec_type != S_LAZY_SYMBOL_POINTERS && sec_type != S_NON_LAZY_SYMBOL_POINTERS {
            return;
        }

        let n_ptrs = (sect.size as usize) / core::mem::size_of::<usize>();
        if n_ptrs == 0 {
            return;
        }

        let start_index = sect.reserved1 as usize;
        let sec_runtime_addr = (sect.addr as i128 + slide as i128) as u64;
        let ptrs = sec_runtime_addr as *mut usize;

        // Heuristic: __DATA_CONST tends to be mapped read-only.
        let segname = cstr_from_fixed_bytes(&sect.segname);
        let should_restore_ro = segname == "__DATA_CONST";

        for j in 0..n_ptrs {
            let sym_index = unsafe { *indirect.add(start_index + j) };
            let slot_ptr = unsafe { ptrs.add(j) };
            let original = unsafe { core::ptr::read_unaligned(slot_ptr) };
            if original == replacement {
                continue;
            }

            // Determine whether this slot corresponds to the desired symbol.
            //
            // Most slots have a valid symtab index and can be matched through the string table.
            // Some binaries use symbol pointers even for local-to-image symbols (interposable
            // call stubs); those are marked as LOCAL/ABS. For these, fall back to dladdr() on
            // the current slot value.
            let matches = if sym_index == INDIRECT_SYMBOL_LOCAL || sym_index == INDIRECT_SYMBOL_ABS {
                let mut info: Dl_info = unsafe { core::mem::zeroed() };
                unsafe {
                    if dladdr(original as *const c_void, &mut info) == 0 || info.dli_sname.is_null() {
                        false
                    } else {
                        core::ffi::CStr::from_ptr(info.dli_sname).to_bytes() == want
                    }
                }
            } else {
                if sym_index >= symtab.nsyms {
                    continue;
                }

                let sym = unsafe { &*symbols.add(sym_index as usize) };
                let strx = unsafe { sym.n_un.n_strx } as usize;
                if strx == 0 || strx >= symtab.strsize as usize {
                    continue;
                }
                let name_ptr = unsafe { strings.add(strx) } as *const c_char;
                let name = unsafe { core::ffi::CStr::from_ptr(name_ptr) }.to_bytes();
                name == want
            };

            if !matches {
                continue;
            }

            let slot_u8 = slot_ptr as *mut u8;
            let page = (slot_u8 as usize) & !(page_sz - 1);
            let page_ptr = page as *mut u8;

            // Make writable, patch, and optionally restore to read-only.
            if libc::mprotect(page_ptr as *mut _, page_sz, libc::PROT_READ | libc::PROT_WRITE) != 0 {
                // Some hardened binaries have read-only __DATA_CONST mappings where
                // libc's mprotect fails; try Mach directly as a fallback.
                let kr = unsafe {
                    mach_vm_protect(
                        mach_task_self(),
                        page as u64,
                        page_sz as u64,
                        0,
                        VM_PROT_READ | VM_PROT_WRITE,
                    )
                };
                if kr != KERN_SUCCESS {
                    if std::env::var_os("MALWI_HOOK_DEBUG").is_some() {
                        let errno = *libc::__error();
                        eprintln!(
                            "[malwi-intercept] rebind_symbol: protect RW failed errno={} kr={} page=0x{:x}",
                            errno, kr, page
                        );
                    }
                    continue;
                }
            }

            unsafe { core::ptr::write_unaligned(slot_ptr, replacement) };
            if let Some(ref mut out) = patched {
                out.push((slot_ptr as usize, original));
            }

            if should_restore_ro {
                let _ = libc::mprotect(page_ptr as *mut _, page_sz, libc::PROT_READ);
            }
        }
    });

    Ok(())
}

/// # Safety
/// `replacement` must be a valid function pointer with the same signature as `symbol`.
pub unsafe fn rebind_symbol(symbol: &str, replacement: usize) -> Result<Vec<(usize, usize)>, HookError> {
    ensure_rebinding_callback_registered();

    let want: Vec<u8> = if symbol.starts_with('_') {
        symbol.as_bytes().to_vec()
    } else {
        let mut v = Vec::with_capacity(symbol.len() + 1);
        v.push(b'_');
        v.extend_from_slice(symbol.as_bytes());
        v
    };

    {
        let mut guard = rebindings().lock().unwrap();
        if !guard.iter().any(|b| b.want == want && b.replacement == replacement) {
            guard.push(Rebinding {
                want: want.clone(),
                replacement,
            });
        }
    }

    let count = _dyld_image_count();
    let mut patched: Vec<(usize, usize)> = Vec::new();
    for i in 0..count {
        let header = _dyld_get_image_header(i);
        if header.is_null() || (*header).magic != MH_MAGIC_64 {
            continue;
        }
        let slide = _dyld_get_image_vmaddr_slide(i);
        let _ = rebind_symbol_in_image(header, slide, &want, replacement, Some(&mut patched));
    }

    if patched.is_empty() {
        return Err(HookError::WrongSignature);
    }
    Ok(patched)
}

/// Rebind raw pointers inside a given module by scanning its writable segments for
/// word-sized values matching `old_value` and replacing them with `replacement`.
///
/// This is useful on macOS when inline patching of `__TEXT` is not possible, but
/// the runtime dispatches through tables stored in `__DATA` / `__DATA_CONST`.
///
/// Returns the number of pointers patched.
///
/// # Safety
/// `replacement` must be a valid function pointer. Callers must ensure the old value is a valid pointer being replaced.
pub unsafe fn rebind_pointers_by_value(
    module_name: &str,
    old_value: usize,
    replacement: usize,
) -> Result<usize, HookError> {
    if old_value == 0 || old_value == replacement {
        return Ok(0);
    }

    let module = find_module_by_name(module_name).ok_or(HookError::WrongSignature)?;
    let count = _dyld_image_count();
    let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;

    for i in 0..count {
        let header = _dyld_get_image_header(i);
        if header.is_null() || (*header).magic != MH_MAGIC_64 {
            continue;
        }

        let name_ptr = _dyld_get_image_name(i);
        let path = if name_ptr.is_null() {
            String::new()
        } else {
            core::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
        };
        if basename(&path) != module.name {
            continue;
        }

        let slide = _dyld_get_image_vmaddr_slide(i);
        let mut patched = 0usize;
        let mut current_page: usize = 0;
        let mut page_is_writable: bool = false;

        for_each_segment_64(header, |seg| {
            let segname = cstr_from_fixed_bytes(&seg.segname);

            // Limit scanning to non-text segments.
            if segname == "__TEXT" || seg.vmsize == 0 {
                return;
            }
            // Focus on data/auth segments where function-pointer tables live.
            if !(segname.starts_with("__DATA") || segname.starts_with("__AUTH")) {
                return;
            }

            let start = (seg.vmaddr as i128 + slide as i128) as usize;
            let size = seg.vmsize as usize;
            let end = start.saturating_add(size);

            let mut p = start;
            while p.saturating_add(core::mem::size_of::<usize>()) <= end {
                let slot = p as *mut usize;
                let value = core::ptr::read_unaligned(slot);
                if value == old_value {
                    let page = p & !(page_sz - 1);
                    if page != current_page {
                        current_page = page;
                        page_is_writable = false;

                        // Try making the page writable. Most __DATA pages already are.
                        if libc::mprotect(
                            page as *mut _,
                            page_sz,
                            libc::PROT_READ | libc::PROT_WRITE,
                        ) == 0
                        {
                            page_is_writable = true;
                        } else {
                            let kr = mach_vm_protect(
                                mach_task_self(),
                                page as u64,
                                page_sz as u64,
                                0,
                                VM_PROT_READ | VM_PROT_WRITE,
                            );
                            page_is_writable = kr == KERN_SUCCESS;
                        }
                    }

                    if page_is_writable {
                        core::ptr::write_unaligned(slot, replacement);
                        patched += 1;
                    }
                }
                p = p.saturating_add(core::mem::size_of::<usize>());
            }
        });

        if patched == 0 {
            return Err(HookError::WrongSignature);
        }
        return Ok(patched);
    }

    Err(HookError::WrongSignature)
}

pub fn resolve_address_module(address: usize) -> Option<String> {
    unsafe {
        let mut info: Dl_info = core::mem::zeroed();
        if dladdr(address as *const c_void, &mut info) == 0 {
            return None;
        }
        if info.dli_fname.is_null() {
            return None;
        }
        let path = core::ffi::CStr::from_ptr(info.dli_fname).to_string_lossy();
        Some(basename(&path).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[no_mangle]
    #[inline(never)]
    pub extern "C" fn malwi_intercept_test_symbol() -> u32 {
        123
    }

    #[test]
    fn enumerate_modules_finds_system_libs() {
        let modules = enumerate_modules();
        assert!(!modules.is_empty());

        let has_system = modules.iter().any(|m| m.name.contains("libSystem") || m.name.contains("dyld"));
        assert!(has_system, "modules: {:?}", modules.iter().map(|m| &m.name).collect::<Vec<_>>());
    }

    #[test]
    fn find_export_resolves_malloc() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        assert_ne!(malloc_addr, 0);
    }

    #[test]
    fn find_export_in_module_resolves_malloc() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let addr = find_export_by_name(&module_name, "malloc").expect("malloc in its defining module");
        assert_ne!(addr, 0);
    }

    #[test]
    fn find_export_returns_error_for_missing() {
        assert!(find_global_export_by_name("this_symbol_definitely_does_not_exist_xyz123").is_err());
    }

    #[test]
    fn enumerate_exports_returns_libc_symbols() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let exports = enumerate_exports(&module_name).expect("enumerate exports");
        let names: std::collections::HashSet<_> = exports.iter().map(|e| e.name.as_str()).collect();
        // Note: exact set varies by OS version, but these are ubiquitous.
        assert!(names.contains("malloc"), "missing malloc");
        assert!(names.contains("free"), "missing free");
    }

    #[test]
    fn module_info_has_valid_ranges() {
        for m in enumerate_modules() {
            if m.size > 0 {
                assert!(m.base_address > 0);
            }
        }
    }

    #[test]
    fn enumerate_symbols_finds_symbol_in_main_executable() {
        // Ensure the symbol is retained by the linker (avoid dead-strip).
        assert_eq!(malwi_intercept_test_symbol(), 123);

        // In release builds the executable name (current_exe) may not match the
        // dyld "image name" we use for lookups. Use dladdr on the known symbol
        // address to pick the correct module robustly.
        let module_name = resolve_address_module(malwi_intercept_test_symbol as *const () as usize)
            .expect("dladdr should find module for test symbol");

        let symbols = enumerate_symbols(&module_name).expect("enumerate symbols");
        assert!(
            symbols.iter().any(|s| s.name.contains("malwi_intercept_test_symbol")),
            "missing symbol in main executable; module_name={module_name}, symbols_len={}",
            symbols.len()
        );
    }

    #[test]
    fn rebind_symbol_can_intercept_posix_spawn_in_this_binary() {
        // Validates the fishhook-style rebinding mechanism by rebinding
        // `posix_spawn` in the current process, then calling it.
        static CALLED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn wrapper(
            pid: *mut libc::pid_t,
            path: *const c_char,
            file_actions: *const libc::posix_spawn_file_actions_t,
            attrp: *const libc::posix_spawnattr_t,
            argv: *const *mut c_char,
            envp: *const *mut c_char,
        ) -> libc::c_int {
            CALLED.fetch_add(1, Ordering::SeqCst);

            // Call the real function via RTLD_NEXT to avoid recursion.
            let mut original =
                libc::dlsym(libc::RTLD_NEXT, c"posix_spawn".as_ptr());
            if original.is_null() {
                // Try underscore form for Mach-O symbol naming.
                original =
                    libc::dlsym(libc::RTLD_NEXT, c"_posix_spawn".as_ptr());
            }
            assert!(!original.is_null(), "failed to resolve original posix_spawn");

            type FnT = unsafe extern "C" fn(
                *mut libc::pid_t,
                *const c_char,
                *const libc::posix_spawn_file_actions_t,
                *const libc::posix_spawnattr_t,
                *const *mut c_char,
                *const *mut c_char,
            ) -> libc::c_int;
            let f: FnT = core::mem::transmute(original);
            f(pid, path, file_actions, attrp, argv, envp)
        }

        unsafe fn restore_slots(patched: &[(usize, usize)]) {
            let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            for (slot, original) in patched {
                let slot_ptr = *slot as *mut usize;
                let page = (slot_ptr as usize) & !(page_sz - 1);
                let _ = libc::mprotect(
                    page as *mut _,
                    page_sz,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                core::ptr::write_unaligned(slot_ptr, *original);
            }
        }

        let patched =
            unsafe { rebind_symbol("posix_spawn", wrapper as *const () as usize) }.expect("should patch slots");
        assert!(!patched.is_empty());

        let mut pid: libc::pid_t = 0;
        let path = std::ffi::CString::new("/usr/bin/true").unwrap();
        let arg0 = std::ffi::CString::new("true").unwrap();
        let argv: [*mut c_char; 2] = [arg0.as_ptr() as *mut c_char, core::ptr::null_mut()];
        let rc = unsafe {
            libc::posix_spawn(
                &mut pid as *mut _,
                path.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                argv.as_ptr(),
                core::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "posix_spawn should succeed");
        assert!(pid > 0, "posix_spawn should return a pid");

        let mut status: libc::c_int = 0;
        let _ = unsafe { libc::waitpid(pid, &mut status, 0) };

        assert!(CALLED.load(Ordering::SeqCst) > 0, "expected wrapper to be called");

        unsafe { restore_slots(&patched) };
    }
}
