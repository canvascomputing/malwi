//! Unpacking a downloaded artefact into a tree a scan can walk. Every entry is
//! hostile input, the archive having been published by whoever malwi is about
//! to investigate, so entries are filtered one at a time rather than handed to
//! an unpack-everything call.

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Ceiling on what one artefact may expand to. A few hundred kilobytes of
/// archive can otherwise name terabytes of output.
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

/// What one artefact expanded to. `skipped` is counted rather than dropped
/// silently: a package that ships an escaping path or a symlink is the finding.
#[derive(Default)]
pub(crate) struct Unpacked {
    pub(crate) files: usize,
    pub(crate) skipped: usize,
    pub(crate) bytes: u64,
}

/// Unpack `file` into `dest`, or `Ok(None)` when the name says malwi opens no
/// archive of this kind. An unknown extension is not a failure: the artefact
/// stays on disk exactly as published.
pub(crate) fn extract(file: &Path, dest: &Path) -> Result<Option<Unpacked>, String> {
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let tarball = name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".crate");
    let zipped = name.ends_with(".zip") || name.ends_with(".whl") || name.ends_with(".egg");
    if !tarball && !zipped {
        return Ok(None);
    }
    fs::create_dir_all(dest).map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    match tarball {
        true => tarball_into(file, dest).map(Some),
        false => zip_into(file, dest).map(Some),
    }
}

/// The path an entry may be written to, or `None` when it would leave `dest`.
/// Refused rather than normalized: dropping a `..` still writes the file, just
/// somewhere else.
fn safe_join(dest: &Path, entry: &Path) -> Option<PathBuf> {
    let mut target = dest.to_path_buf();
    for component in entry.components() {
        match component {
            Component::Normal(part) => target.push(part),
            _ => return None,
        }
    }
    (target != dest).then_some(target)
}

/// Write one entry's bytes. The reader is capped at what is left of the budget
/// rather than trusted, so a header understating its own size buys nothing.
fn write_entry(
    source: &mut impl Read,
    target: &Path,
    unpacked: &mut Unpacked,
) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let remaining = MAX_UNPACKED_BYTES - unpacked.bytes;
    let mut out =
        fs::File::create(target).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    let written = io::copy(&mut source.take(remaining + 1), &mut out)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    if written > remaining {
        return Err(format!(
            "the archive expands past the {MAX_UNPACKED_BYTES} byte limit"
        ));
    }
    unpacked.bytes += written;
    unpacked.files += 1;
    Ok(())
}

fn tarball_into(file: &Path, dest: &Path) -> Result<Unpacked, String> {
    let opened =
        fs::File::open(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let decoded = flate2::read::GzDecoder::new(io::BufReader::new(opened));
    let mut archive = tar::Archive::new(decoded);
    let entries = archive
        .entries()
        .map_err(|e| format!("{} is not a readable tar: {e}", file.display()))?;

    let mut unpacked = Unpacked::default();
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("{} ends mid-entry: {e}", file.display()))?;
        let kind = entry.header().entry_type();
        let path = entry
            .path()
            .map_err(|e| format!("{} names an unreadable path: {e}", file.display()))?
            .into_owned();
        let Some(target) = safe_join(dest, &path) else {
            unpacked.skipped += 1;
            continue;
        };
        if kind.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
            continue;
        }
        if !kind.is_file() {
            unpacked.skipped += 1;
            continue;
        }
        write_entry(&mut entry, &target, &mut unpacked)?;
    }
    Ok(unpacked)
}

fn zip_into(file: &Path, dest: &Path) -> Result<Unpacked, String> {
    let opened =
        fs::File::open(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let mut archive = zip::ZipArchive::new(io::BufReader::new(opened))
        .map_err(|e| format!("{} is not a readable zip: {e}", file.display()))?;

    let mut unpacked = Unpacked::default();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("{} has an unreadable entry: {e}", file.display()))?;
        let target = entry
            .enclosed_name()
            .and_then(|name| safe_join(dest, &name));
        let Some(target) = target else {
            unpacked.skipped += 1;
            continue;
        };
        if entry.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
            continue;
        }
        if !entry.is_file() {
            unpacked.skipped += 1;
            continue;
        }
        write_entry(&mut entry, &target, &mut unpacked)?;
    }
    Ok(unpacked)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESCAPING_ENTRY: &str = "../escaped.txt";
    const PAYLOAD: &[u8] = b"print('hello')\n";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("malwi-archive-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a temp directory");
        dir
    }

    /// The name is written into the header field rather than through
    /// `append_data`, which refuses a path holding `..` — the very entry these
    /// tests exist to feed the extractor.
    fn tarball(dir: &Path, entries: &[(&str, tar::EntryType)]) -> PathBuf {
        let file = dir.join("sample.tar.gz");
        let out = fs::File::create(&file).expect("a tarball to write");
        let encoder = flate2::write::GzEncoder::new(out, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, kind) in entries {
            let data: &[u8] = match *kind == tar::EntryType::Symlink {
                true => &[],
                false => PAYLOAD,
            };
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_entry_type(*kind);
            header.set_mode(0o644);
            if *kind == tar::EntryType::Symlink {
                header.set_link_name("/etc/passwd").expect("a link target");
            }
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder.append(&header, data).expect("an entry to append");
        }
        builder
            .into_inner()
            .expect("a finished tar")
            .finish()
            .expect("a finished gzip");
        file
    }

    #[test]
    fn an_entry_pointing_outside_the_destination_writes_nothing() {
        let dir = temp_dir("escape");
        let file = tarball(&dir, &[(ESCAPING_ENTRY, tar::EntryType::Regular)]);
        let dest = dir.join("out");

        let unpacked = extract(&file, &dest)
            .expect("a readable tarball")
            .expect("a tarball");

        assert_eq!(unpacked.files, 0);
        assert_eq!(unpacked.skipped, 1);
        assert!(!dir.join("escaped.txt").exists());
    }

    #[test]
    fn a_symlink_entry_is_skipped_rather_than_created() {
        let dir = temp_dir("symlink");
        let file = tarball(
            &dir,
            &[
                ("package/keys.txt", tar::EntryType::Symlink),
                ("package/setup.py", tar::EntryType::Regular),
            ],
        );
        let dest = dir.join("out");

        let unpacked = extract(&file, &dest)
            .expect("a readable tarball")
            .expect("a tarball");

        assert_eq!(unpacked.files, 1);
        assert_eq!(unpacked.skipped, 1);
        assert!(!dest.join("package/keys.txt").exists());
        assert_eq!(
            fs::read(dest.join("package/setup.py")).expect("the regular entry"),
            PAYLOAD
        );
    }

    #[test]
    fn an_artefact_of_an_unknown_kind_is_left_as_published() {
        let dir = temp_dir("opaque");
        let file = dir.join("model.bin");
        fs::write(&file, PAYLOAD).expect("an artefact");

        assert!(extract(&file, &dir.join("out"))
            .expect("an unknown kind is not a failure")
            .is_none());
    }
}
