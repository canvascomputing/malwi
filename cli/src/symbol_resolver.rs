//! CLI-side symbol resolution for native stack traces.
//!
//! Resolves raw addresses captured by the agent into symbol names using
//! the module maps sent during the ready handshake and the `object` crate
//! for parsing symbol tables from on-disk binaries.

use std::collections::HashMap;

use log::debug;
use malwi_protocol::NativeFrame;
use malwi_protocol::protocol::ModuleInfo;

/// Cached symbol table for a single binary file.
struct ModuleSymbols {
    /// Sorted by address: (file_offset, symbol_name)
    symbols: Vec<(u64, String)>,
}

/// Flattened module range for O(log n) binary search.
struct ModuleRange {
    base: u64,
    end: u64,
    pid: u32,
    module_idx: usize,
}

/// Resolves native stack frame addresses to symbol names.
pub struct SymbolResolver {
    /// Per-PID module maps (base_address, size, name, path).
    module_maps: HashMap<u32, Vec<ModuleInfo>>,
    /// Cached parsed symbol tables keyed by file path.
    symbol_cache: HashMap<String, Option<ModuleSymbols>>,
    /// Sorted module ranges for O(log n) lookup.
    sorted_ranges: Vec<ModuleRange>,
}

impl SymbolResolver {
    pub fn new() -> Self {
        Self {
            module_maps: HashMap::new(),
            symbol_cache: HashMap::new(),
            sorted_ranges: Vec::new(),
        }
    }

    /// Store a module map for a given PID and rebuild the sorted index.
    pub fn add_module_map(&mut self, pid: u32, modules: Vec<ModuleInfo>) {
        debug!("Added module map for PID {}: {} modules", pid, modules.len());
        self.module_maps.insert(pid, modules);
        self.rebuild_sorted_ranges();
    }

    /// Rebuild the flattened sorted range index from all module maps.
    fn rebuild_sorted_ranges(&mut self) {
        self.sorted_ranges.clear();
        for (&pid, modules) in &self.module_maps {
            for (idx, m) in modules.iter().enumerate() {
                self.sorted_ranges.push(ModuleRange {
                    base: m.base_address,
                    end: m.base_address + m.size,
                    pid,
                    module_idx: idx,
                });
            }
        }
        self.sorted_ranges.sort_by_key(|r| r.base);
    }

    /// Resolve a single native frame using all known module maps.
    pub fn resolve_frame(&mut self, frame: &NativeFrame) -> NativeFrame {
        let addr = frame.address as u64;

        // O(log n) binary search for containing module
        let pos = self.sorted_ranges.partition_point(|r| r.base <= addr);
        let found_module: Option<&ModuleInfo> = if pos > 0 {
            let range = &self.sorted_ranges[pos - 1];
            if addr < range.end {
                self.module_maps
                    .get(&range.pid)
                    .and_then(|m| m.get(range.module_idx))
            } else {
                None
            }
        } else {
            None
        };

        let module = match found_module {
            Some(m) => m,
            None => return frame.clone(), // No module found, return unchanged
        };

        let file_offset = addr - module.base_address;
        let module_name = module.name.clone();
        let module_path = module.path.clone();

        // Load/cache symbols for this module
        let symbols = self.load_symbols(&module_path);

        match symbols {
            Some(syms) if !syms.symbols.is_empty() => {
                // Binary search for nearest symbol at or before file_offset
                let idx = syms.symbols.partition_point(|(a, _)| *a <= file_offset);
                if idx > 0 {
                    let (sym_addr, sym_name) = &syms.symbols[idx - 1];
                    let sym_offset = file_offset - sym_addr;
                    NativeFrame {
                        address: frame.address,
                        symbol: Some(sym_name.clone()),
                        module: Some(module_name),
                        offset: Some(sym_offset as usize),
                    }
                } else {
                    // No symbol before this offset
                    NativeFrame {
                        address: frame.address,
                        symbol: None,
                        module: Some(module_name),
                        offset: Some(file_offset as usize),
                    }
                }
            }
            _ => {
                // No symbols available, but we know the module
                NativeFrame {
                    address: frame.address,
                    symbol: None,
                    module: Some(module_name),
                    offset: Some(file_offset as usize),
                }
            }
        }
    }

    /// Resolve a raw address into a NativeFrame.
    pub fn resolve_address(&mut self, addr: usize) -> NativeFrame {
        let frame = NativeFrame {
            address: addr,
            symbol: None,
            module: None,
            offset: None,
        };
        self.resolve_frame(&frame)
    }

    /// Resolve a slice of raw addresses into NativeFrames.
    pub fn resolve_addresses(&mut self, addresses: &[usize]) -> Vec<NativeFrame> {
        addresses.iter().map(|&addr| self.resolve_address(addr)).collect()
    }

    /// Remove module maps for a given PID and rebuild sorted ranges.
    pub fn remove_pid(&mut self, pid: u32) {
        if self.module_maps.remove(&pid).is_some() {
            self.rebuild_sorted_ranges();
        }
    }

    /// Load and cache symbols for a module binary.
    fn load_symbols(&mut self, path: &str) -> Option<&ModuleSymbols> {
        if !self.symbol_cache.contains_key(path) {
            let syms = Self::parse_symbols(path);
            self.symbol_cache.insert(path.to_string(), syms);
        }
        self.symbol_cache.get(path).and_then(|s| s.as_ref())
    }

    /// Parse symbol table from a binary file.
    fn parse_symbols(path: &str) -> Option<ModuleSymbols> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                debug!("Failed to read binary {}: {}", path, e);
                return None;
            }
        };

        let obj = match object::File::parse(&*data) {
            Ok(f) => f,
            Err(e) => {
                debug!("Failed to parse binary {}: {}", path, e);
                return None;
            }
        };

        use object::ObjectSymbol;
        use object::Object;

        let mut symbols: Vec<(u64, String)> = Vec::new();

        // Collect from both symbol tables
        for sym in obj.symbols().chain(obj.dynamic_symbols()) {
            if sym.address() == 0 {
                continue;
            }
            let name = match sym.name() {
                Ok(n) if !n.is_empty() => n,
                _ => continue,
            };

            // Strip leading underscore on macOS (Mach-O convention)
            let clean_name = if cfg!(target_os = "macos") {
                name.strip_prefix('_').unwrap_or(name)
            } else {
                name
            };

            symbols.push((sym.address(), clean_name.to_string()));
        }

        // Sort by address for binary search
        symbols.sort_by_key(|(addr, _)| *addr);

        // Deduplicate by address (keep first name)
        symbols.dedup_by_key(|(addr, _)| *addr);

        debug!("Parsed {} symbols from {}", symbols.len(), path);

        Some(ModuleSymbols { symbols })
    }

    #[cfg(test)]
    pub fn symbol_cache_len(&self) -> usize {
        self.symbol_cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(addr: usize) -> NativeFrame {
        NativeFrame {
            address: addr,
            symbol: None,
            module: None,
            offset: None,
        }
    }

    #[test]
    fn test_resolve_frame_finds_module() {
        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, vec![
            ModuleInfo {
                name: "test_lib".to_string(),
                path: "/nonexistent/test_lib.so".to_string(),
                base_address: 0x1000,
                size: 0x5000,
            },
        ]);

        let frame = make_frame(0x2000);
        let resolved = resolver.resolve_frame(&frame);

        assert_eq!(resolved.module.as_deref(), Some("test_lib"));
        assert_eq!(resolved.offset, Some(0x1000)); // 0x2000 - 0x1000
    }

    #[test]
    fn test_resolve_frame_unknown_address() {
        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, vec![
            ModuleInfo {
                name: "test_lib".to_string(),
                path: "/nonexistent/test_lib.so".to_string(),
                base_address: 0x1000,
                size: 0x5000,
            },
        ]);

        let frame = make_frame(0xDEAD);
        let resolved = resolver.resolve_frame(&frame);

        // Outside any module range — returned unchanged
        assert!(resolved.symbol.is_none());
        assert!(resolved.module.is_none());
        assert!(resolved.offset.is_none());
    }

    #[test]
    fn test_resolve_frame_parses_real_binary() {
        let exe = std::env::current_exe().expect("should get current exe");
        let exe_str = exe.to_string_lossy().to_string();

        // Parse the binary's symbols to find a known address
        let syms = SymbolResolver::parse_symbols(&exe_str);
        assert!(syms.is_some(), "Should parse test binary");
        let syms = syms.unwrap();
        assert!(!syms.symbols.is_empty(), "Should have symbols");

        // Pick a symbol that exists and try to resolve it
        let (sym_addr, sym_name) = &syms.symbols[syms.symbols.len() / 2]; // pick one from the middle

        let mut resolver = SymbolResolver::new();
        // Use base_address = 0 since object crate returns virtual addresses
        resolver.add_module_map(1, vec![
            ModuleInfo {
                name: "test_binary".to_string(),
                path: exe_str,
                base_address: 0,
                size: u64::MAX,
            },
        ]);

        let frame = make_frame(*sym_addr as usize);
        let resolved = resolver.resolve_frame(&frame);

        assert!(
            resolved.symbol.is_some(),
            "Expected resolved symbol, got None for address {:#x} (expected '{}')",
            sym_addr, sym_name
        );
        assert_eq!(
            resolved.symbol.as_deref(),
            Some(sym_name.as_str()),
            "Expected symbol '{}' at address {:#x}",
            sym_name, sym_addr
        );
        assert_eq!(resolved.offset, Some(0), "Offset should be 0 for exact symbol address");
    }

    #[test]
    fn test_symbol_cache_reused() {
        let exe = std::env::current_exe().expect("should get current exe");
        let exe_str = exe.to_string_lossy().to_string();

        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, vec![
            ModuleInfo {
                name: "test_binary".to_string(),
                path: exe_str,
                base_address: 0,
                size: u64::MAX,
            },
        ]);

        // Resolve two different frames from the same module
        let _ = resolver.resolve_frame(&make_frame(0x100));
        let _ = resolver.resolve_frame(&make_frame(0x200));

        // Cache should have exactly one entry
        assert_eq!(resolver.symbol_cache_len(), 1);
    }

    #[test]
    fn test_stripped_binary_fallback() {
        let mut resolver = SymbolResolver::new();
        // Point at /dev/null — not a valid binary
        resolver.add_module_map(1, vec![
            ModuleInfo {
                name: "stripped_lib".to_string(),
                path: "/dev/null".to_string(),
                base_address: 0x1000,
                size: 0x5000,
            },
        ]);

        let frame = make_frame(0x2000);
        let resolved = resolver.resolve_frame(&frame);

        // Should fall back to module name + offset
        assert_eq!(resolved.module.as_deref(), Some("stripped_lib"));
        assert_eq!(resolved.offset, Some(0x1000));
        assert!(resolved.symbol.is_none());
    }

    #[test]
    fn test_macos_underscore_stripping() {
        // This test verifies the parse_symbols logic strips leading _ on macOS
        // by checking the actual test binary's symbols
        if !cfg!(target_os = "macos") {
            eprintln!("SKIPPED: macOS-specific test");
            return;
        }

        let exe = std::env::current_exe().expect("should get current exe");
        let exe_str = exe.to_string_lossy().to_string();

        let syms = SymbolResolver::parse_symbols(&exe_str);
        assert!(syms.is_some(), "Should parse test binary symbols");

        let syms = syms.unwrap();
        // On macOS, no symbol should start with _ (they should be stripped)
        // (except symbols that legitimately start with _ in their unmangled form)
        let has_main = syms.symbols.iter().any(|(_, name)| name == "main");
        assert!(
            has_main,
            "Expected to find 'main' (without leading _) in macOS binary symbols"
        );
    }
}
