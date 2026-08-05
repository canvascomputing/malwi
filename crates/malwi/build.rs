//! Generates the attack-pattern page table from whatever sits in
//! `src/attacks/`, so adding a page is dropping in a file.

use std::fmt::Write as _;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let pages_dir = Path::new(&manifest_dir).join("src").join("attacks");
    println!("cargo:rerun-if-changed={}", pages_dir.display());

    let entries = std::fs::read_dir(&pages_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", pages_dir.display()));

    let mut pages: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let path = entry.expect("directory entry is readable").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let slug = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("page name is not UTF-8: {}", path.display()))
            .to_string();
        let file = path
            .to_str()
            .unwrap_or_else(|| panic!("page path is not UTF-8: {}", path.display()))
            .to_string();
        pages.push((slug, file));
    }
    // Sort so the generated table is stable across filesystems and reruns.
    pages.sort();

    let mut table = String::from(
        "/// The attack-pattern pages as `(slug, page)`, embedded at compile time so an\n\
         /// installed binary carries its own seed instead of reading the source tree.\n\
         pub(crate) const PAGES: &[(&str, &str)] = &[\n",
    );
    for (slug, file) in &pages {
        writeln!(table, "    ({slug:?}, include_str!({file:?})),").expect("String never fails");
    }
    table.push_str("];\n");

    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let out_file = Path::new(&out_dir).join("attacks.rs");
    std::fs::write(&out_file, table)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out_file.display()));
}
