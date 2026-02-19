use crate::types::{ExportInfo, HookError, ModuleInfo};
use core::ffi::{c_char, c_void};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::sync::Mutex;

/// Pre-parsed .symtab/.strtab section offsets, cached once per file.
#[derive(Clone, Copy)]
struct SymtabInfo {
    symtab_off: usize,
    symtab_size: usize,
    symtab_entsize: usize,
    strtab_off: usize,
    strtab_size: usize,
    is_dyn: bool,
    file_base_vma: u64,
}

/// An mmap'd ELF file with pre-parsed section metadata.
struct MmapElfFile {
    data: *const u8,
    size: usize,
    symtab: Option<SymtabInfo>,
}

// Safety: read-only mmap, never munmap'd, valid for process lifetime.
unsafe impl Send for MmapElfFile {}
unsafe impl Sync for MmapElfFile {}

static MMAP_CACHE: Mutex<Option<HashMap<String, Option<MmapElfFile>>>> = Mutex::new(None);

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Enumerate all loaded shared objects via `dl_iterate_phdr`.
pub fn enumerate_modules() -> Vec<ModuleInfo> {
    struct Ctx {
        modules: Vec<ModuleInfo>,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> libc::c_int {
        let ctx = &mut *(data as *mut Ctx);
        let info = &*info;

        let path = if info.dlpi_name.is_null() || *info.dlpi_name == 0 {
            // Empty name means the main executable. Read from /proc/self/exe.
            match std::fs::read_link("/proc/self/exe") {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => String::new(),
            }
        } else {
            CStr::from_ptr(info.dlpi_name)
                .to_string_lossy()
                .into_owned()
        };

        // Compute module size from PT_LOAD segments.
        let mut min_addr: Option<u64> = None;
        let mut max_addr: u64 = 0;
        let phdrs = core::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
        for phdr in phdrs {
            if phdr.p_type == libc::PT_LOAD && phdr.p_memsz > 0 {
                let start = phdr.p_vaddr;
                let end = start + phdr.p_memsz;
                min_addr = Some(min_addr.map(|m: u64| m.min(start)).unwrap_or(start));
                max_addr = max_addr.max(end);
            }
        }

        let base = info.dlpi_addr as usize + min_addr.unwrap_or(0) as usize;
        let size = if let Some(min) = min_addr {
            (max_addr - min) as usize
        } else {
            0
        };

        let name = if path.is_empty() {
            String::from("[unknown]")
        } else {
            basename(&path).to_string()
        };

        ctx.modules.push(ModuleInfo {
            name,
            path,
            base_address: base,
            size,
        });

        0 // continue iteration
    }

    let mut ctx = Ctx {
        modules: Vec::new(),
    };

    unsafe {
        libc::dl_iterate_phdr(Some(callback), &mut ctx as *mut Ctx as *mut c_void);
    }

    ctx.modules
}

pub fn find_module_by_name(name: &str) -> Option<ModuleInfo> {
    enumerate_modules()
        .into_iter()
        .find(|m| m.name == name || m.path.ends_with(name))
}

/// Resolve a symbol globally (across all loaded modules) using `dlsym(RTLD_DEFAULT, ...)`.
pub fn find_global_export_by_name(symbol: &str) -> Result<usize, HookError> {
    let cstr = std::ffi::CString::new(symbol).map_err(|_| HookError::WrongSignature)?;
    unsafe {
        let p = libc::dlsym(libc::RTLD_DEFAULT, cstr.as_ptr());
        if p.is_null() {
            Err(HookError::WrongSignature)
        } else {
            Ok(p as usize)
        }
    }
}

/// Resolve a symbol within a specific module using `dlopen(RTLD_NOLOAD) + dlsym`.
pub fn find_export_by_name(module_name: &str, symbol: &str) -> Result<usize, HookError> {
    let module = find_module_by_name(module_name).ok_or(HookError::WrongSignature)?;

    let sym_cstr = std::ffi::CString::new(symbol).map_err(|_| HookError::WrongSignature)?;

    // Try the full path first, then the basename.
    for path in &[&module.path, &module.name] {
        if path.is_empty() {
            continue;
        }
        let Ok(path_cstr) = std::ffi::CString::new(path.as_str()) else {
            continue;
        };
        unsafe {
            let handle = libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_NOW);
            if handle.is_null() {
                continue;
            }
            let p = libc::dlsym(handle, sym_cstr.as_ptr());
            libc::dlclose(handle);
            if !p.is_null() {
                return Ok(p as usize);
            }
        }
    }

    // Fall back to global lookup.
    find_global_export_by_name(symbol)
}

// ELF type definitions for parsing dynamic symbol tables from memory.
mod elf {
    pub const DT_NULL: i64 = 0;
    pub const DT_STRTAB: i64 = 5;
    pub const DT_SYMTAB: i64 = 6;
    pub const DT_HASH: i64 = 4;
    pub const DT_GNU_HASH: i64 = 0x6ffffef5;

    pub const STB_GLOBAL: u8 = 1;
    pub const STB_WEAK: u8 = 2;
    pub const SHN_UNDEF: u16 = 0;

    pub const STT_FUNC: u8 = 2;
    pub const STT_OBJECT: u8 = 1;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Elf64Sym {
        pub st_name: u32,
        pub st_info: u8,
        pub st_other: u8,
        pub st_shndx: u16,
        pub st_value: u64,
        pub st_size: u64,
    }

    impl Elf64Sym {
        pub fn st_bind(&self) -> u8 {
            self.st_info >> 4
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Elf64Dyn {
        pub d_tag: i64,
        pub d_val: u64, // d_un union, d_val / d_ptr
    }

    // ELF hash table
    #[repr(C)]
    pub struct ElfHash {
        pub nbucket: u32,
        pub nchain: u32,
        // followed by: bucket[nbucket], chain[nchain]
    }
}

/// Enumerate dynamic exports from a module's in-memory ELF image.
///
/// Walks the PT_DYNAMIC segment to find DT_SYMTAB, DT_STRTAB, and DT_HASH/DT_GNU_HASH,
/// then iterates the symbol table for exported symbols.
pub fn enumerate_exports(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    enumerate_dynamic_symbols(module_name, true)
}

/// Enumerate all symbols (dynamic + disk .symtab) from a module.
///
/// Disk I/O is cached via mmap (OS page cache handles memory pressure).
pub fn enumerate_symbols(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    let mut syms = enumerate_dynamic_symbols(module_name, false)?;

    // Also read the full .symtab from disk (contains local symbols not in dynamic table).
    if let Some(module) = find_module_by_name(module_name) {
        if !module.path.is_empty() {
            if let Ok((data, size, info)) = get_or_create_mmap(&module.path) {
                let disk_syms = walk_symtab_from_mmap(data, size, &info, module.base_address);
                let existing: HashSet<usize> = syms.iter().map(|s| s.address).collect();
                for s in disk_syms {
                    if !existing.contains(&s.address) {
                        syms.push(s);
                    }
                }
            }
        }
    }

    Ok(syms)
}

fn enumerate_dynamic_symbols(
    module_name: &str,
    only_exports: bool,
) -> Result<Vec<ExportInfo>, HookError> {
    struct Ctx {
        module_name: String,
        only_exports: bool,
        result: Option<Vec<ExportInfo>>,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> libc::c_int {
        let ctx = &mut *(data as *mut Ctx);
        if ctx.result.is_some() {
            return 1; // already found
        }

        let info = &*info;
        let path = if info.dlpi_name.is_null() || *info.dlpi_name == 0 {
            match std::fs::read_link("/proc/self/exe") {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => String::new(),
            }
        } else {
            CStr::from_ptr(info.dlpi_name)
                .to_string_lossy()
                .into_owned()
        };

        let name = if path.is_empty() {
            "[unknown]".to_string()
        } else {
            basename(&path).to_string()
        };

        if name != ctx.module_name && !path.ends_with(&ctx.module_name) {
            return 0; // continue
        }

        // Find PT_DYNAMIC segment.
        let phdrs = core::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
        let mut dynamic_ptr: *const elf::Elf64Dyn = core::ptr::null();
        for phdr in phdrs {
            if phdr.p_type == libc::PT_DYNAMIC {
                dynamic_ptr = (info.dlpi_addr + phdr.p_vaddr) as *const elf::Elf64Dyn;
                break;
            }
        }
        if dynamic_ptr.is_null() {
            return 0;
        }

        // Walk DT entries to find SYMTAB, STRTAB, HASH/GNU_HASH.
        // DT entries contain virtual addresses. For most shared libraries loaded
        // by ld.so, these are already relocated to absolute runtime addresses
        // ("adjusted"). But for kernel-injected modules like linux-vdso.so.1,
        // they may be pristine file virtual addresses that need the base added.
        let mut symtab_val: u64 = 0;
        let mut strtab_val: u64 = 0;
        let mut hash_val: u64 = 0;
        let mut gnu_hash_val: u64 = 0;

        let mut dyn_entry = dynamic_ptr;
        loop {
            let entry = &*dyn_entry;
            if entry.d_tag == elf::DT_NULL {
                break;
            }
            match entry.d_tag {
                elf::DT_SYMTAB => symtab_val = entry.d_val,
                elf::DT_STRTAB => strtab_val = entry.d_val,
                elf::DT_HASH => hash_val = entry.d_val,
                elf::DT_GNU_HASH => gnu_hash_val = entry.d_val,
                _ => {}
            }
            dyn_entry = dyn_entry.add(1);
        }

        if symtab_val == 0 || strtab_val == 0 {
            return 0;
        }

        // Detect if DT addresses are pristine or adjusted:
        // if DT_SYMTAB or DT_STRTAB > base_address, they're already absolute.
        let base = info.dlpi_addr;
        let adjusted = symtab_val > base || strtab_val > base;
        let resolve = |val: u64| -> usize {
            if adjusted {
                val as usize
            } else {
                (base + val) as usize
            }
        };

        let symtab = resolve(symtab_val) as *const elf::Elf64Sym;
        let strtab = resolve(strtab_val) as *const u8;
        let hash: *const elf::ElfHash = if hash_val != 0 {
            resolve(hash_val) as *const elf::ElfHash
        } else {
            core::ptr::null()
        };
        let gnu_hash_ptr: *const u8 = if gnu_hash_val != 0 {
            resolve(gnu_hash_val) as *const u8
        } else {
            core::ptr::null()
        };

        // Determine number of symbols from hash table.
        let nsyms = if !hash.is_null() {
            (*hash).nchain as usize
        } else if !gnu_hash_ptr.is_null() {
            gnu_hash_nsyms(gnu_hash_ptr)
        } else {
            return 0;
        };

        let base_usize = base as usize;
        let mut exports = Vec::new();

        for i in 0..nsyms {
            let sym = &*symtab.add(i);
            if sym.st_shndx == elf::SHN_UNDEF || sym.st_value == 0 {
                continue;
            }
            if sym.st_name == 0 {
                continue;
            }

            if ctx.only_exports {
                let bind = sym.st_bind();
                if bind != elf::STB_GLOBAL && bind != elf::STB_WEAK {
                    continue;
                }
            }

            let name_ptr = strtab.add(sym.st_name as usize) as *const c_char;
            let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();

            exports.push(ExportInfo {
                name,
                address: base_usize + sym.st_value as usize,
            });
        }

        ctx.result = Some(exports);
        1 // stop iteration
    }

    let mut ctx = Ctx {
        module_name: module_name.to_string(),
        only_exports,
        result: None,
    };

    unsafe {
        libc::dl_iterate_phdr(Some(callback), &mut ctx as *mut Ctx as *mut c_void);
    }

    ctx.result.ok_or(HookError::WrongSignature)
}

/// Compute the number of symbols from a GNU hash table.
///
/// GNU hash tables don't store nchain directly. We have to scan the
/// chain array to find the highest symbol index.
unsafe fn gnu_hash_nsyms(gnu_hash: *const u8) -> usize {
    // GNU hash layout:
    //   u32 nbuckets
    //   u32 symoffset  (index of first symbol in hash)
    //   u32 bloom_size
    //   u32 bloom_shift
    //   u64[bloom_size] bloom filter
    //   u32[nbuckets] buckets
    //   u32[] chains (one per symbol starting from symoffset)
    let nbuckets = *(gnu_hash as *const u32);
    let symoffset = *((gnu_hash as *const u32).add(1));
    let bloom_size = *((gnu_hash as *const u32).add(2));

    let bloom = (gnu_hash as *const u32).add(4) as *const u64;
    let buckets = bloom.add(bloom_size as usize) as *const u32;
    let chains = buckets.add(nbuckets as usize);

    // Find the maximum bucket value (highest starting symbol index).
    let mut max_sym: u32 = 0;
    for i in 0..nbuckets {
        let b = *buckets.add(i as usize);
        if b > max_sym {
            max_sym = b;
        }
    }

    if max_sym < symoffset {
        return symoffset as usize;
    }

    // Walk the chain from max_sym until we find the terminating entry (bit 0 set).
    let mut idx = max_sym;
    loop {
        let chain_entry = *chains.add((idx - symoffset) as usize);
        if chain_entry & 1 != 0 {
            break;
        }
        idx += 1;
    }

    (idx + 1) as usize
}

/// Open and mmap an ELF file, parsing section headers to find SHT_SYMTAB.
fn mmap_elf_file(path: &str) -> Result<MmapElfFile, HookError> {
    let c_path = std::ffi::CString::new(path).map_err(|_| HookError::WrongSignature)?;

    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return Err(HookError::WrongSignature);
        }

        let mut st: libc::stat = core::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 || st.st_size < 64 {
            libc::close(fd);
            return Err(HookError::WrongSignature);
        }
        let size = st.st_size as usize;

        let ptr = libc::mmap(
            core::ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        libc::close(fd);

        if ptr == libc::MAP_FAILED {
            return Err(HookError::WrongSignature);
        }

        let data = ptr as *const u8;
        let bytes = core::slice::from_raw_parts(data, size);

        // Verify ELF magic.
        if &bytes[0..4] != b"\x7fELF" {
            return Ok(MmapElfFile {
                data,
                size,
                symtab: None,
            });
        }

        // Parse ELF64 header.
        let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
        let e_shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;

        if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
            return Ok(MmapElfFile {
                data,
                size,
                symtab: None,
            });
        }

        // Validate section header string table index.
        {
            let sh_offset = e_shoff + e_shstrndx * e_shentsize;
            if sh_offset + e_shentsize > size {
                return Ok(MmapElfFile {
                    data,
                    size,
                    symtab: None,
                });
            }
        }

        // Find SHT_SYMTAB section.
        const SHT_SYMTAB: u32 = 2;
        let mut symtab_off: usize = 0;
        let mut symtab_size: usize = 0;
        let mut symtab_entsize: usize = 0;
        let mut symtab_link: usize = 0;

        for i in 0..e_shnum {
            let sh_offset = e_shoff + i * e_shentsize;
            if sh_offset + e_shentsize > size {
                break;
            }
            let sh_type =
                u32::from_le_bytes(bytes[sh_offset + 4..sh_offset + 8].try_into().unwrap());
            if sh_type == SHT_SYMTAB {
                symtab_off =
                    u64::from_le_bytes(bytes[sh_offset + 24..sh_offset + 32].try_into().unwrap())
                        as usize;
                symtab_size =
                    u64::from_le_bytes(bytes[sh_offset + 32..sh_offset + 40].try_into().unwrap())
                        as usize;
                symtab_entsize =
                    u64::from_le_bytes(bytes[sh_offset + 56..sh_offset + 64].try_into().unwrap())
                        as usize;
                symtab_link =
                    u32::from_le_bytes(bytes[sh_offset + 40..sh_offset + 44].try_into().unwrap())
                        as usize;
                break;
            }
        }

        if symtab_off == 0 || symtab_entsize == 0 {
            return Ok(MmapElfFile {
                data,
                size,
                symtab: None,
            });
        }

        // Get the linked string table.
        let strtab_sh_offset = e_shoff + symtab_link * e_shentsize;
        if strtab_sh_offset + e_shentsize > size {
            return Ok(MmapElfFile {
                data,
                size,
                symtab: None,
            });
        }
        let strtab_off = u64::from_le_bytes(
            bytes[strtab_sh_offset + 24..strtab_sh_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let strtab_size = u64::from_le_bytes(
            bytes[strtab_sh_offset + 32..strtab_sh_offset + 40]
                .try_into()
                .unwrap(),
        ) as usize;

        if strtab_off + strtab_size > size || symtab_off + symtab_size > size {
            return Ok(MmapElfFile {
                data,
                size,
                symtab: None,
            });
        }

        // Determine is_dyn and file_base_vma.
        let e_type = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
        let is_dyn = e_type == 3; // ET_DYN

        let mut file_base_vma: u64 = 0;
        if is_dyn {
            let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
            let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
            let e_phnum = u16::from_le_bytes(bytes[52..54].try_into().unwrap()) as usize;

            let mut min_vaddr: Option<u64> = None;
            for i in 0..e_phnum {
                let ph_offset = e_phoff + i * e_phentsize;
                if ph_offset + e_phentsize > size {
                    break;
                }
                let p_type =
                    u32::from_le_bytes(bytes[ph_offset..ph_offset + 4].try_into().unwrap());
                if p_type == 1 {
                    let p_vaddr = u64::from_le_bytes(
                        bytes[ph_offset + 16..ph_offset + 24].try_into().unwrap(),
                    );
                    min_vaddr = Some(min_vaddr.map(|m: u64| m.min(p_vaddr)).unwrap_or(p_vaddr));
                }
            }
            file_base_vma = min_vaddr.unwrap_or(0);
        }

        Ok(MmapElfFile {
            data,
            size,
            symtab: Some(SymtabInfo {
                symtab_off,
                symtab_size,
                symtab_entsize,
                strtab_off,
                strtab_size,
                is_dyn,
                file_base_vma,
            }),
        })
    }
}

/// Walk the mmap'd .symtab using pre-parsed offsets to produce symbols.
fn walk_symtab_from_mmap(
    data: *const u8,
    size: usize,
    info: &SymtabInfo,
    base_address: usize,
) -> Vec<ExportInfo> {
    let bytes = unsafe { core::slice::from_raw_parts(data, size) };
    let nsyms = info.symtab_size / info.symtab_entsize;
    let mut exports = Vec::new();

    for i in 0..nsyms {
        let sym_off = info.symtab_off + i * info.symtab_entsize;
        if sym_off + 24 > size {
            break;
        }

        let st_name = u32::from_le_bytes(bytes[sym_off..sym_off + 4].try_into().unwrap()) as usize;
        let st_info = bytes[sym_off + 4];
        let st_shndx = u16::from_le_bytes(bytes[sym_off + 6..sym_off + 8].try_into().unwrap());
        let st_value = u64::from_le_bytes(bytes[sym_off + 8..sym_off + 16].try_into().unwrap());

        if st_value == 0 || st_shndx == 0 || st_name == 0 {
            continue;
        }

        let st_type = st_info & 0xf;
        if st_type != elf::STT_FUNC && st_type != elf::STT_OBJECT {
            continue;
        }

        if st_name >= info.strtab_size {
            continue;
        }

        let name_start = info.strtab_off + st_name;
        let name_end = bytes[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start);
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned();

        let address = if info.is_dyn {
            base_address + (st_value - info.file_base_vma) as usize
        } else {
            st_value as usize
        };

        exports.push(ExportInfo { name, address });
    }

    exports
}

/// Get or create an mmap'd ELF file entry from the cache.
///
/// Returns the raw pointer, size, and pre-parsed SymtabInfo. The pointer remains
/// valid after releasing the lock because mmap entries are never removed or munmap'd.
fn get_or_create_mmap(path: &str) -> Result<(*const u8, usize, SymtabInfo), HookError> {
    let mut cache = MMAP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = cache.get_or_insert_with(HashMap::new);

    if !map.contains_key(path) {
        let entry = mmap_elf_file(path).ok();
        map.insert(path.to_string(), entry);
    }

    match map.get(path).unwrap() {
        None => Err(HookError::WrongSignature),
        Some(elf) => match elf.symtab {
            None => Err(HookError::WrongSignature),
            Some(info) => Ok((elf.data, elf.size, info)),
        },
    }
}

/// Read the full `.symtab` section from an ELF file on disk.
///
/// This provides local symbols that aren't in the dynamic symbol table.
#[cfg(test)]
fn read_elf_symtab_from_disk(
    path: &str,
    base_address: usize,
) -> Result<Vec<ExportInfo>, HookError> {
    let (data, size, info) = get_or_create_mmap(path)?;
    let syms = walk_symtab_from_mmap(data, size, &info, base_address);
    if syms.is_empty() {
        Err(HookError::WrongSignature)
    } else {
        Ok(syms)
    }
}

/// Resolve which module an address belongs to via `dladdr`.
pub fn resolve_address_module(address: usize) -> Option<String> {
    unsafe {
        let mut info: libc::Dl_info = core::mem::zeroed();
        if libc::dladdr(address as *const c_void, &mut info) == 0 {
            return None;
        }
        if info.dli_fname.is_null() {
            return None;
        }
        let path = CStr::from_ptr(info.dli_fname).to_string_lossy();
        Some(basename(&path).to_string())
    }
}

/// Rebind symbol via ELF GOT patching (Linux equivalent of macOS fishhook).
///
/// Scans `.got` and `.got.plt` across all loaded modules for entries pointing
/// to the target symbol's address, and replaces them with `replacement`.
///
/// # Safety
/// The caller must ensure `replacement` points to a valid function with the
/// same signature as the original symbol.
pub unsafe fn rebind_symbol(
    symbol: &str,
    replacement: usize,
) -> Result<Vec<(usize, usize)>, HookError> {
    // Resolve the original address of the symbol.
    let original_addr = find_global_export_by_name(symbol)?;

    let mut patched: Vec<(usize, usize)> = Vec::new();

    struct Ctx {
        original_addr: usize,
        replacement: usize,
        patched: *mut Vec<(usize, usize)>,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> libc::c_int {
        let ctx = &*(data as *const Ctx);
        let info = &*info;
        let base = info.dlpi_addr as usize;

        let phdrs = core::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);

        // Find PT_DYNAMIC.
        let mut dynamic_ptr: *const elf::Elf64Dyn = core::ptr::null();
        for phdr in phdrs {
            if phdr.p_type == libc::PT_DYNAMIC {
                dynamic_ptr = (base as u64 + phdr.p_vaddr) as *const elf::Elf64Dyn;
                break;
            }
        }
        if dynamic_ptr.is_null() {
            return 0;
        }

        // Walk DT entries to find GOT-related relocations.
        // Handle pristine vs adjusted DT addresses (same as enumerate_dynamic_symbols).
        let mut jmprel_val: u64 = 0;
        let mut jmprel_size: usize = 0;
        let mut rela_val: u64 = 0;
        let mut rela_size: usize = 0;
        let mut symtab_val: u64 = 0;
        let mut strtab_val: u64 = 0;

        const DT_JMPREL: i64 = 23;
        const DT_PLTRELSZ: i64 = 2;
        const DT_RELA: i64 = 7;
        const DT_RELASZ: i64 = 8;

        let mut dyn_entry = dynamic_ptr;
        loop {
            let entry = &*dyn_entry;
            if entry.d_tag == elf::DT_NULL {
                break;
            }
            match entry.d_tag {
                DT_JMPREL => jmprel_val = entry.d_val,
                DT_PLTRELSZ => jmprel_size = entry.d_val as usize,
                DT_RELA => rela_val = entry.d_val,
                DT_RELASZ => rela_size = entry.d_val as usize,
                elf::DT_SYMTAB => symtab_val = entry.d_val,
                elf::DT_STRTAB => strtab_val = entry.d_val,
                _ => {}
            }
            dyn_entry = dyn_entry.add(1);
        }

        let base_u64 = info.dlpi_addr;
        let adjusted = symtab_val > base_u64 || strtab_val > base_u64;
        let resolve = |val: u64| -> *const u8 {
            if val == 0 {
                return core::ptr::null();
            }
            if adjusted {
                val as *const u8
            } else {
                (base_u64 + val) as *const u8
            }
        };

        let jmprel = resolve(jmprel_val);
        let rela = resolve(rela_val);

        let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;

        // Scan GOT entries from JMPREL (.got.plt) and RELA (.got).
        for (rel_ptr, rel_size) in [(jmprel, jmprel_size), (rela, rela_size)] {
            if rel_ptr.is_null() || rel_size == 0 {
                continue;
            }

            const RELA_ENTRY_SIZE: usize = 24;
            let nrels = rel_size / RELA_ENTRY_SIZE;

            for i in 0..nrels {
                let entry = rel_ptr.add(i * RELA_ENTRY_SIZE);
                let r_offset = *(entry as *const u64);
                // r_info is at offset 8
                // r_addend is at offset 16

                let got_addr = base + r_offset as usize;
                let got_slot = got_addr as *mut usize;
                let current_value = core::ptr::read_unaligned(got_slot);

                if current_value == ctx.original_addr {
                    let page = got_addr & !(page_sz - 1);
                    let _ = libc::mprotect(
                        page as *mut libc::c_void,
                        page_sz,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    core::ptr::write_unaligned(got_slot, ctx.replacement);
                    (*ctx.patched).push((got_addr, current_value));
                }
            }
        }

        0 // continue
    }

    let mut ctx = Ctx {
        original_addr,
        replacement,
        patched: &mut patched,
    };

    libc::dl_iterate_phdr(Some(callback), &mut ctx as *mut Ctx as *mut c_void);

    if patched.is_empty() {
        Err(HookError::WrongSignature)
    } else {
        Ok(patched)
    }
}

/// Rebind raw pointers by scanning writable segments for word-sized values
/// matching `old_value` and replacing them with `replacement`.
///
/// # Safety
/// The caller must ensure `replacement` is a valid pointer value suitable for
/// replacing `old_value` in all writable segments of the specified module.
pub unsafe fn rebind_pointers_by_value(
    module_name: &str,
    old_value: usize,
    replacement: usize,
) -> Result<usize, HookError> {
    if old_value == 0 || old_value == replacement {
        return Ok(0);
    }

    struct Ctx {
        module_name: String,
        old_value: usize,
        replacement: usize,
        patched: usize,
        found: bool,
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> libc::c_int {
        let ctx = &mut *(data as *mut Ctx);
        if ctx.found {
            return 1;
        }

        let info = &*info;
        let path = if info.dlpi_name.is_null() || *info.dlpi_name == 0 {
            match std::fs::read_link("/proc/self/exe") {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => String::new(),
            }
        } else {
            CStr::from_ptr(info.dlpi_name)
                .to_string_lossy()
                .into_owned()
        };

        let name = if path.is_empty() {
            "[unknown]".to_string()
        } else {
            basename(&path).to_string()
        };

        if name != ctx.module_name && !path.ends_with(&ctx.module_name) {
            return 0;
        }

        ctx.found = true;
        let base = info.dlpi_addr as usize;
        let phdrs = core::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
        let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let mut current_page: usize = 0;
        let mut page_is_writable = false;

        for phdr in phdrs {
            if phdr.p_type != libc::PT_LOAD || phdr.p_memsz == 0 {
                continue;
            }
            // Only scan writable segments.
            if phdr.p_flags & libc::PF_W == 0 {
                continue;
            }

            let start = base + phdr.p_vaddr as usize;
            let end = start + phdr.p_memsz as usize;

            let mut p = start;
            while p + core::mem::size_of::<usize>() <= end {
                let slot = p as *mut usize;
                let value = core::ptr::read_unaligned(slot);
                if value == ctx.old_value {
                    let page = p & !(page_sz - 1);
                    if page != current_page {
                        current_page = page;
                        page_is_writable = libc::mprotect(
                            page as *mut libc::c_void,
                            page_sz,
                            libc::PROT_READ | libc::PROT_WRITE,
                        ) == 0;
                    }
                    if page_is_writable {
                        core::ptr::write_unaligned(slot, ctx.replacement);
                        ctx.patched += 1;
                    }
                }
                p += core::mem::size_of::<usize>();
            }
        }

        1
    }

    let mut ctx = Ctx {
        module_name: module_name.to_string(),
        old_value,
        replacement,
        patched: 0,
        found: false,
    };

    libc::dl_iterate_phdr(Some(callback), &mut ctx as *mut Ctx as *mut c_void);

    if !ctx.found {
        return Err(HookError::WrongSignature);
    }
    if ctx.patched == 0 {
        return Err(HookError::WrongSignature);
    }
    Ok(ctx.patched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_modules_finds_libc() {
        let modules = enumerate_modules();
        assert!(!modules.is_empty());
        let has_libc = modules
            .iter()
            .any(|m| m.name.contains("libc") || m.name.contains("ld-linux"));
        assert!(
            has_libc,
            "modules: {:?}",
            modules.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn find_export_resolves_malloc() {
        let addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        assert_ne!(addr, 0);
    }

    #[test]
    fn find_export_in_module_resolves_malloc() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let addr =
            find_export_by_name(&module_name, "malloc").expect("malloc in its defining module");
        assert_ne!(addr, 0);
    }

    #[test]
    fn find_export_returns_error_for_missing() {
        assert!(
            find_global_export_by_name("this_symbol_definitely_does_not_exist_xyz123").is_err()
        );
    }

    #[test]
    fn enumerate_exports_returns_libc_symbols() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let exports = enumerate_exports(&module_name).expect("enumerate exports");
        let names: std::collections::HashSet<_> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains("malloc"), "missing malloc in exports");
        assert!(names.contains("free"), "missing free in exports");
    }

    #[test]
    fn module_info_has_valid_ranges() {
        for m in enumerate_modules() {
            if m.size > 0 {
                assert!(
                    m.base_address > 0,
                    "module {} has zero base with size {}",
                    m.name,
                    m.size
                );
            }
        }
    }

    #[test]
    fn enumerate_symbols_finds_malloc() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let symbols = enumerate_symbols(&module_name).expect("enumerate symbols");
        assert!(
            symbols.iter().any(|s| s.name == "malloc"),
            "missing malloc in symbols; module_name={module_name}, symbols_len={}",
            symbols.len()
        );
    }

    /// Scan all modules for a missing symbol (mimics setup_bash_hooks behavior).
    /// This should NOT crash even if some modules have unusual ELF layouts.
    #[test]
    fn scan_all_modules_for_missing_symbol_no_crash() {
        let modules = enumerate_modules();
        eprintln!("scanning {} modules for 'dist_version'", modules.len());
        for m in &modules {
            eprintln!("  scanning: {} (path: {})", m.name, m.path);
            match enumerate_symbols(&m.name) {
                Ok(syms) => {
                    let has = syms.iter().any(|s| s.name == "dist_version");
                    eprintln!("    {} symbols, has dist_version: {}", syms.len(), has);
                }
                Err(e) => {
                    eprintln!("    error: {:?}", e);
                }
            }
        }
    }

    #[test]
    fn resolve_address_module_works() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module = resolve_address_module(malloc_addr).expect("should resolve module");
        assert!(!module.is_empty());
    }

    /// Test that enumerate_symbols reads disk .symtab for the test binary itself.
    /// Regression test: read_elf_symtab_from_disk must correctly parse
    /// Elf64_Shdr.sh_link (at offset 40) to find the string table for .symtab.
    #[test]
    fn enumerate_symbols_finds_local_symbols_from_disk() {
        let exe_path = std::fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        let exe_name = exe_path.file_name().unwrap().to_string_lossy().to_string();

        let module = find_module_by_name(&exe_name);
        assert!(
            module.is_some(),
            "Should find test binary module '{}'",
            exe_name
        );
        let module = module.unwrap();

        // read_elf_symtab_from_disk must return symbols from the on-disk .symtab.
        let syms = read_elf_symtab_from_disk(&module.path, module.base_address)
            .expect("read_elf_symtab_from_disk should succeed");
        assert!(
            syms.len() > 10,
            "Should find local symbols; got {}",
            syms.len()
        );

        // All returned symbols must have non-empty names (string table was resolved).
        assert!(
            syms.iter().all(|s| !s.name.is_empty()),
            "All symbols should have resolved names"
        );

        // enumerate_symbols should include these disk symbols.
        let all_syms = enumerate_symbols(&exe_name).expect("enumerate_symbols");
        assert!(
            all_syms.len() >= syms.len(),
            "enumerate_symbols should include disk symbols"
        );
    }

    #[test]
    fn mmap_elf_file_returns_error_for_nonexistent_path() {
        let result = mmap_elf_file("/tmp/this_path_does_not_exist_xyz");
        assert!(result.is_err(), "should fail for nonexistent path");
    }

    #[test]
    fn mmap_elf_file_returns_none_symtab_for_non_elf_file() {
        // /etc/hosts is reliably >= 64 bytes and not an ELF file.
        let result = mmap_elf_file("/etc/hosts");
        let elf = result.expect("mmap should succeed for regular file");
        assert!(
            elf.symtab.is_none(),
            "non-ELF file should have symtab: None"
        );
    }

    #[test]
    fn mmap_elf_file_returns_error_for_tiny_file() {
        let path = "/tmp/malwi_test_tiny_file";
        std::fs::write(path, b"tiny").expect("write temp file");
        let result = mmap_elf_file(path);
        std::fs::remove_file(path).ok();
        assert!(result.is_err(), "should fail for file < 64 bytes");
    }

    #[test]
    fn mmap_elf_file_parses_symtab() {
        // Use the test binary itself — it has .symtab (not stripped during testing).
        let exe_path = std::fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        let path = exe_path.to_string_lossy();
        let elf = mmap_elf_file(&path).expect("mmap test binary");
        let info = elf.symtab.expect("test binary should have .symtab section");
        assert_eq!(info.symtab_entsize, 24, "Elf64_Sym size should be 24");
        assert!(info.is_dyn, "PIE test binary should be ET_DYN");
        assert!(info.symtab_off > 0, "symtab offset should be non-zero");
        assert!(info.strtab_off > 0, "strtab offset should be non-zero");
    }

    #[test]
    fn walk_symtab_from_mmap_produces_symbols() {
        // Use the test binary — guaranteed to have .symtab with local symbols.
        let exe_path = std::fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        let exe_name = exe_path.file_name().unwrap().to_string_lossy().to_string();
        let module = find_module_by_name(&exe_name).expect("find test binary module");
        let elf = mmap_elf_file(&module.path).expect("mmap test binary");
        let info = elf.symtab.expect("test binary should have .symtab");
        let syms = walk_symtab_from_mmap(elf.data, elf.size, &info, module.base_address);
        assert!(!syms.is_empty(), "should produce symbols from .symtab");
        assert!(
            syms.iter().all(|s| !s.name.is_empty()),
            "all symbols should have resolved names"
        );
        assert!(
            syms.iter().all(|s| s.address > 0),
            "all symbols should have non-zero addresses"
        );
    }

    #[test]
    fn get_or_create_mmap_caches_successful_result() {
        // Use the test binary — guaranteed to have .symtab so get_or_create_mmap succeeds.
        let exe_path = std::fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        let path = exe_path.to_string_lossy().to_string();
        let (ptr1, size1, _) = get_or_create_mmap(&path).expect("first call");
        let (ptr2, size2, _) = get_or_create_mmap(&path).expect("second call");
        assert_eq!(ptr1, ptr2, "cached pointer should be identical");
        assert_eq!(size1, size2, "cached size should be identical");
    }

    #[test]
    fn get_or_create_mmap_caches_failed_path() {
        let path = "/tmp/nonexistent_file_xyz_mmap_cache_test";
        let r1 = get_or_create_mmap(path);
        let r2 = get_or_create_mmap(path);
        assert!(r1.is_err(), "first call should fail");
        assert!(r2.is_err(), "second call should also fail (cached)");
    }

    #[test]
    fn enumerate_symbols_concurrent_access() {
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc");
        let module_name = resolve_address_module(malloc_addr).expect("module");
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let name = module_name.clone();
                std::thread::spawn(move || {
                    let syms = enumerate_symbols(&name).expect("enumerate_symbols");
                    assert!(
                        syms.iter().any(|s| s.name == "malloc"),
                        "should find malloc"
                    );
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    #[test]
    fn mmap_elf_file_handles_stripped_binary() {
        let out = "/tmp/malwi_stripped_test_binary";
        let status = std::process::Command::new("strip")
            .args(["--strip-all", "-o", out, "/proc/self/exe"])
            .status();
        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("strip not available, skipping test");
                return;
            }
        }
        let elf = mmap_elf_file(out).expect("mmap stripped binary");
        std::fs::remove_file(out).ok();
        assert!(
            elf.symtab.is_none(),
            "stripped binary should have no .symtab"
        );
    }
}
