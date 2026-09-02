//! Seeds a `Knowledge` store from the attack-pattern pages under
//! `attacks/`, real supply-chain hiding techniques
//! (see roles/seeker.md, roles/tracer.md).

use std::io;
use std::path::{Path, PathBuf};

use agentwerk::agents::knowledge::Page;

include!(concat!(env!("OUT_DIR"), "/attacks.rs"));

/// Where the pages live inside a source checkout, and where `malwi research`
/// installs a new one unless `--knowledge` names somewhere else.
const SOURCE_DIR: &str = "crates/malwi/src/attacks";

/// Write every attack-pattern page into `<dir>/knowledge/pages/`, so a
/// subsequent `Knowledge::load(dir.join("knowledge"))` indexes them like any
/// other seeded bundle.
/// Both the Tracer's and the Seeker's stores are wiped and rebuilt from these
/// pages each run.
pub(crate) fn copy_seed_into(dir: &Path) -> io::Result<()> {
    let dest = dir.join("knowledge").join("pages");
    std::fs::create_dir_all(&dest)?;
    for &(slug, page) in PAGES {
        std::fs::write(dest.join(format!("{slug}.md")), page)?;
    }
    Ok(())
}

/// True when the slug names a page the binary already carries, so research
/// neither rediscovers nor overwrites an incident already covered.
pub(crate) fn is_seeded(slug: &str) -> bool {
    PAGES.iter().any(|(seeded, _)| *seeded == slug)
}

/// Where a researched page lands. A source checkout takes it directly, so the
/// next build embeds it; anywhere else falls back to the run's own folder,
/// since an installed binary has no source tree to extend.
pub(crate) fn install_dir(fallback_dir: &Path) -> PathBuf {
    let source_dir = PathBuf::from(SOURCE_DIR);
    if source_dir.is_dir() {
        source_dir
    } else {
        fallback_dir.to_path_buf()
    }
}

/// Write one researched page into the install directory under its slug, in the
/// corpus form. The front matter is rewritten rather than carried over: the
/// knowledge store stamps its own `type` and timestamp, and only `AttackPattern`
/// belongs in the seed the scanner reads.
pub(crate) fn install(page: &Page, dir: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let page_file = dir.join(format!("{}.md", page.slug));
    std::fs::write(&page_file, render(page))?;
    Ok(page_file)
}

fn render(page: &Page) -> String {
    let tags = match page.tags.is_empty() {
        true => String::new(),
        false => format!("tags: [{}]\n", page.tags.join(", ")),
    };
    format!(
        "---\ntype: AttackPattern\ndescription: {}\n{tags}---\n{}\n",
        page.description.trim(),
        page.content.trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentwerk::Knowledge;

    #[test]
    fn seeded_store_indexes_every_attack_pattern_page() {
        let dir = std::env::temp_dir().join(format!("attacks_seed_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        copy_seed_into(&dir).unwrap();
        let knowledge = Knowledge::load(dir.join("knowledge")).unwrap();
        let index = knowledge.get_index();

        let _ = std::fs::remove_dir_all(&dir);
        assert!(!PAGES.is_empty(), "the generated table should list pages");
        for &(slug, _) in PAGES {
            assert!(index.contains(slug), "index should list {slug}: {index}");
        }
    }

    /// Guards the seed round-trip: an installed page must parse back into the
    /// store the same way a hand-written one does.
    #[test]
    fn an_installed_page_carries_the_corpus_front_matter() {
        let dir = std::env::temp_dir().join(format!("attacks_install_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let page = Page {
            slug: "a-new-campaign".to_string(),
            kind: "Knowledge".to_string(),
            description: "A campaign that hid a payload in a lockfile.".to_string(),
            content: "# A campaign\n\n## Carrier\nan npm lockfile".to_string(),
            tags: Vec::new(),
        };

        let page_file = install(&page, &dir).unwrap();

        let written = std::fs::read_to_string(&page_file).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            written.starts_with("---\ntype: AttackPattern\n"),
            "{written}"
        );
        assert!(written.contains("hid a payload in a lockfile"), "{written}");
        assert!(written.contains("## Carrier"), "{written}");
        assert_eq!(
            written.matches("---").count(),
            2,
            "one front matter: {written}"
        );
    }

    #[test]
    fn a_page_the_binary_carries_is_recognized_as_seeded() {
        assert!(is_seeded("xz-utils-liblzma-backdoor"));
        assert!(!is_seeded("some-campaign-nobody-has-written-up"));
    }

    /// Guards the corpus contract: a hand-written page and a researched one are
    /// read by the same agents, so they carry the same OKF frontmatter and the
    /// same sections. Divergence here is what makes one page unreadable to a
    /// Seeker that learned the shape from another.
    #[test]
    fn every_page_carries_the_okf_frontmatter_and_the_five_sections() {
        const SECTIONS: [&str; 5] = [
            "## Carrier",
            "## Technique",
            "## Payload/effect",
            "## Detectable signal",
            "## Sources",
        ];
        for &(slug, page) in PAGES {
            let (frontmatter, body) = page
                .strip_prefix("---\n")
                .and_then(|rest| rest.split_once("\n---\n"))
                .unwrap_or_else(|| panic!("{slug}: page opens with OKF frontmatter"));

            assert!(
                frontmatter.starts_with("type: AttackPattern"),
                "{slug}: frontmatter declares the OKF type first",
            );
            for key in ["description:", "tags: ["] {
                assert!(frontmatter.contains(key), "{slug}: frontmatter has {key}");
            }
            for section in SECTIONS {
                assert!(
                    body.contains(&format!("\n{section}\n")),
                    "{slug}: body has {section}",
                );
            }
            assert!(body.starts_with("# "), "{slug}: body opens with its title");
        }
    }

    /// Guards the point of the corpus: a page listing only one incident's
    /// filenames and hosts catches a replay and nothing else, so every page
    /// states the generalizable shape before its literals.
    #[test]
    fn every_detectable_signal_leads_with_the_generalizable_shape() {
        for &(slug, page) in PAGES {
            let signal = page
                .split_once("## Detectable signal\n")
                .map(|(_, rest)| rest.split("\n## ").next().unwrap_or(rest))
                .unwrap_or_else(|| panic!("{slug}: page has a detectable signal"));
            assert!(
                signal.starts_with("The shape, which catches a variant"),
                "{slug}: the signal leads with the shape, not with literals",
            );
        }
    }

    /// Guards against a page citing nothing: an unsourced claim is what the
    /// research chain's Verifier exists to reject, and a seeded page is held to
    /// the same bar.
    #[test]
    fn every_page_cites_at_least_one_source_url() {
        for &(slug, page) in PAGES {
            let sources = page
                .split_once("## Sources\n")
                .map(|(_, rest)| rest)
                .unwrap_or_else(|| panic!("{slug}: page has sources"));
            let urls = sources.lines().filter(|l| l.starts_with("- http")).count();
            assert!(urls > 0, "{slug}: sources list at least one URL");
        }
    }
}
