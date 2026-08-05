//! Seeds a `Knowledge` store from the attack-pattern pages under
//! `knowledge/attack_patterns/`, real supply-chain hiding techniques
//! (see roles/seeker.md, roles/tracer.md).

use std::io;
use std::path::Path;

/// The attack-pattern pages as `(slug, page)`, embedded at compile time so an
/// installed binary carries its own seed instead of reading the source tree.
const PAGES: [(&str, &str); 12] = [
    (
        "buildrunner-dev-png-steganography",
        include_str!("knowledge/attack_patterns/buildrunner-dev-png-steganography.md"),
    ),
    (
        "event-stream-flatmap-stream",
        include_str!("knowledge/attack_patterns/event-stream-flatmap-stream.md"),
    ),
    (
        "gootloader-font-trick",
        include_str!("knowledge/attack_patterns/gootloader-font-trick.md"),
    ),
    (
        "mut-8694-mut-8964-campaign",
        include_str!("knowledge/attack_patterns/mut-8694-mut-8964-campaign.md"),
    ),
    (
        "node-ipc-protestware",
        include_str!("knowledge/attack_patterns/node-ipc-protestware.md"),
    ),
    (
        "polyfill-io-cdn-takeover",
        include_str!("knowledge/attack_patterns/polyfill-io-cdn-takeover.md"),
    ),
    (
        "shai-hulud-2-maintainer-compromise",
        include_str!("knowledge/attack_patterns/shai-hulud-2-maintainer-compromise.md"),
    ),
    (
        "solana-fakefix",
        include_str!("knowledge/attack_patterns/solana-fakefix.md"),
    ),
    (
        "tj-actions-changed-files-compromise",
        include_str!("knowledge/attack_patterns/tj-actions-changed-files-compromise.md"),
    ),
    (
        "ua-parser-js-hijack",
        include_str!("knowledge/attack_patterns/ua-parser-js-hijack.md"),
    ),
    (
        "xz-utils-liblzma-backdoor",
        include_str!("knowledge/attack_patterns/xz-utils-liblzma-backdoor.md"),
    ),
    (
        "zip-slip-archive-extraction",
        include_str!("knowledge/attack_patterns/zip-slip-archive-extraction.md"),
    ),
];

/// Write every attack-pattern page into `<dir>/knowledge/pages/`, so a
/// subsequent `Knowledge::load(dir)` indexes them like any other seeded bundle.
/// Both the Tracer's and the Seeker's stores are wiped and rebuilt from these
/// pages each run.
pub(crate) fn copy_seed_into(dir: &Path) -> io::Result<()> {
    let dest = dir.join("knowledge").join("pages");
    std::fs::create_dir_all(&dest)?;
    for (slug, page) in PAGES {
        std::fs::write(dest.join(format!("{slug}.md")), page)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentwerk::Knowledge;

    #[test]
    fn seeded_store_indexes_every_attack_pattern_page() {
        let dir = std::env::temp_dir().join(format!("attack_patterns_seed_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        copy_seed_into(&dir).unwrap();
        let knowledge = Knowledge::load(&dir).unwrap();
        let index = knowledge.index();

        let _ = std::fs::remove_dir_all(&dir);
        for (slug, _) in PAGES {
            assert!(index.contains(slug), "index should list {slug}: {index}");
        }
    }
}
