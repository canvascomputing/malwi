//! Native symbol resolution and module enumeration.
//!
//! Provides utilities for finding and enumerating symbols from loaded modules
//! using malwi-hook.

use anyhow::{anyhow, Result};

use crate::glob::{is_glob_pattern, matches_glob};

/// Information about a loaded module.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub size: usize,
}

/// Information about an exported symbol.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: usize,
    pub module: String,
}

/// Enumerate all loaded modules in the current process.
pub fn enumerate_modules() -> Vec<ModuleInfo> {
    malwi_intercept::module::enumerate_modules()
        .into_iter()
        .map(|m| ModuleInfo {
            name: m.name,
            path: m.path,
            base_address: m.base_address,
            size: m.size,
        })
        .collect()
}

/// Enumerate exports from a specific module.
pub fn enumerate_exports(module_name: &str) -> Vec<ExportInfo> {
    match malwi_intercept::module::enumerate_exports(module_name) {
        Ok(exports) => exports
            .into_iter()
            .map(|e| ExportInfo {
                name: e.name,
                address: e.address,
                module: module_name.to_string(),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Information about a symbol (including local/non-exported symbols).
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: usize,
    pub module: String,
    pub is_global: bool,
}

/// Find a symbol by name (including local symbols).
/// Uses malwi_intercept::module::enumerate_symbols to find both exported and local symbols.
pub fn find_symbol(module_name: &str, symbol: &str) -> Result<usize> {
    let symbols = malwi_intercept::module::enumerate_symbols(module_name)
        .map_err(|_| anyhow!("Module not found: {}", module_name))?;
    for s in symbols {
        // Mach-O symbol names are typically prefixed with '_' (e.g. _malloc).
        // Most of malwi's filters use the unprefixed name.
        // Use strip_prefix (not trim_start_matches) to strip exactly one '_'.
        if s.name == symbol || s.name.strip_prefix('_').is_some_and(|n| n == symbol) {
            return Ok(s.address);
        }
    }
    Err(anyhow!("Symbol not found: {} in {}", symbol, module_name))
}

/// Find an exported symbol by name.
pub fn find_export(module: Option<&str>, symbol: &str) -> Result<usize> {
    let address = if let Some(mod_name) = module {
        malwi_intercept::module::find_export_by_name(mod_name, symbol)
    } else {
        malwi_intercept::module::find_global_export_by_name(symbol)
    };

    address.map_err(|_| anyhow!("Symbol not found: {}", symbol))
}

/// Resolve an exported symbol and transmute it to a function pointer type.
///
/// This is a convenience helper that combines `find_export` with `transmute`,
/// providing consistent error logging. Use this instead of repeating the
/// resolve! macro pattern in multiple modules.
///
/// # Safety
/// The caller must ensure that `T` is a function pointer type that matches
/// the actual signature of the resolved symbol.
pub fn resolve_export_as<T>(module: Option<&str>, symbol: &str) -> Option<T> {
    match find_export(module, symbol) {
        Ok(addr) => Some(unsafe { std::mem::transmute_copy(&addr) }),
        Err(e) => {
            log::debug!("Failed to resolve {}: {}", symbol, e);
            None
        }
    }
}

/// Find all exported symbols matching a glob pattern.
/// If pattern has no wildcards, returns single exact match.
/// If pattern has wildcards, enumerates all modules and returns all matches.
/// Deduplicates by symbol name (first match wins, similar to how the dynamic linker resolves symbols).
pub fn find_exports_matching(module: Option<&str>, pattern: &str) -> Vec<ExportInfo> {
    use std::collections::HashSet;
    use log::debug;

    if !is_glob_pattern(pattern) {
        // Exact match - use fast path
        return match find_export(module, pattern) {
            Ok(addr) => vec![ExportInfo {
                name: pattern.to_string(),
                address: addr,
                module: module.unwrap_or("").to_string(),
            }],
            Err(_) => vec![],
        };
    }

    // Glob pattern - enumerate all exports
    let mut matches = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    if let Some(mod_name) = module {
        // Search specific module
        for export in enumerate_exports(mod_name) {
            if matches_glob(pattern, &export.name) && !seen_names.contains(&export.name) {
                debug!("Glob match: {} in {}", export.name, mod_name);

                // Use find_export to get the authoritative address. The address from
                // enumerate_exports() can differ from what the dynamic linker resolves
                // (e.g., for weak symbols or interposed functions). Using find_export
                // ensures we hook the same address that explicit -s hooks would use.
                let final_addr = find_export(Some(mod_name), &export.name)
                    .unwrap_or(export.address);

                seen_names.insert(export.name.clone());
                matches.push(ExportInfo {
                    name: export.name,
                    address: final_addr,
                    module: mod_name.to_string(),
                });
            }
        }
    } else {
        // Search all modules - deduplicate by name (first match wins)
        for module_info in enumerate_modules() {
            for export in enumerate_exports(&module_info.name) {
                if matches_glob(pattern, &export.name) && !seen_names.contains(&export.name) {
                    debug!("Glob match: {} in {}", export.name, module_info.name);

                    // Use find_export for authoritative address (see comment above)
                    let final_addr = find_export(None, &export.name)
                        .unwrap_or(export.address);

                    seen_names.insert(export.name.clone());
                    matches.push(ExportInfo {
                        name: export.name,
                        address: final_addr,
                        module: module_info.name.clone(),
                    });
                }
            }
        }
    }

    matches
}

/// Find all symbols (including non-exported/local) matching a glob pattern.
///
/// This is needed for hooking targets that are not exported from their module
/// (e.g., test fixtures, bash builtins, etc.). On Mach-O, names in the raw
/// symbol table usually start with '_' so we match against the stripped name.
pub fn find_symbols_matching(module: Option<&str>, pattern: &str) -> Vec<ExportInfo> {
    use std::collections::HashSet;
    use log::debug;

    fn normalize(name: &str) -> &str {
        name.strip_prefix('_').unwrap_or(name)
    }

    if !is_glob_pattern(pattern) {
        // Try export fast-path first.
        if let Ok(addr) = find_export(module, pattern) {
            return vec![ExportInfo {
                name: pattern.to_string(),
                address: addr,
                module: module.unwrap_or("").to_string(),
            }];
        }

        // Exact, non-exported symbol: scan symbols in requested module(s).
        let mut out = Vec::new();
        let modules: Vec<ModuleInfo> = if let Some(mod_name) = module {
            enumerate_modules().into_iter().filter(|m| m.name == mod_name).collect()
        } else {
            enumerate_modules()
        };

        for m in modules {
            if let Ok(symbols) = malwi_intercept::module::enumerate_symbols(&m.name) {
                for s in symbols {
                    if normalize(&s.name) == pattern || s.name == pattern {
                        out.push(ExportInfo {
                            name: pattern.to_string(),
                            address: s.address,
                            module: m.name.clone(),
                        });
                        return out;
                    }
                }
            }
        }
        return out;
    }

    // Glob pattern - enumerate all symbols
    let mut matches = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    let modules: Vec<ModuleInfo> = if let Some(mod_name) = module {
        enumerate_modules().into_iter().filter(|m| m.name == mod_name).collect()
    } else {
        enumerate_modules()
    };

    for module_info in modules {
        let symbols = match malwi_intercept::module::enumerate_symbols(&module_info.name) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for sym in symbols {
            let stripped = normalize(&sym.name);
            if matches_glob(pattern, stripped) && !seen_names.contains(stripped) {
                debug!("Glob match (symbol): {} in {}", stripped, module_info.name);
                seen_names.insert(stripped.to_string());
                matches.push(ExportInfo {
                    name: stripped.to_string(),
                    address: sym.address,
                    module: module_info.name.clone(),
                });
            }
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_gum;

    #[test]
    fn test_find_export_returns_address_for_malloc() {
        init_gum();
        // malloc should exist in libc or system library
        let result = find_export(None, "malloc");
        assert!(result.is_ok(), "malloc should be found: {:?}", result.err());
        assert!(result.unwrap() != 0, "malloc address should be non-zero");
    }

    #[test]
    fn test_find_export_returns_address_for_free() {
        init_gum();
        let result = find_export(None, "free");
        assert!(result.is_ok(), "free should be found: {:?}", result.err());
        assert!(result.unwrap() != 0, "free address should be non-zero");
    }

    #[test]
    fn test_find_export_returns_error_for_missing_symbol() {
        init_gum();
        let result = find_export(None, "this_symbol_definitely_does_not_exist_xyz123");
        assert!(result.is_err(), "nonexistent symbol should return error");
    }

    #[test]
    fn test_enumerate_modules_includes_system_libraries() {
        init_gum();
        let modules = enumerate_modules();
        // Should have at least some modules loaded
        assert!(!modules.is_empty(), "Should have at least one module loaded");

        // Should include libc or libSystem on macOS
        let has_system_lib = modules.iter().any(|m| {
            m.name.contains("libc")
                || m.name.contains("libSystem")
                || m.name.contains("dyld")
        });
        assert!(has_system_lib, "Should find system library. Found: {:?}",
            modules.iter().map(|m| &m.name).collect::<Vec<_>>());
    }

}
