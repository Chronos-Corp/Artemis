use anyhow::{bail, Context, Result};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

/// Maximum byte snapshot accepted by ordinary Artemis hash and YARA
/// analysis. Explicit sample retrieval may choose a smaller protocol limit.
pub const MAX_ANALYSIS_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashResult {
    pub sha256: String,
    pub md5: String,
}

/// One validated, bounded snapshot of the object that was actually opened.
///
/// `size_at_open` and `modified_at_open` come from metadata on the same
/// open handle as `bytes`. A regular file may still change while it is
/// read, so consumers that require a stable identity hash `bytes` itself;
/// they must not treat the metadata as content identity.
#[derive(Debug)]
pub struct FileSnapshot {
    pub bytes: Vec<u8>,
    pub size_at_open: u64,
    pub modified_at_open: SystemTime,
}

/// Opens and reads one regular file through a single handle, with a hard
/// byte ceiling.
///
/// On Unix, the open uses `O_NONBLOCK` so a path swapped to a FIFO between
/// discovery and inspection cannot block forever before validation. The
/// final target is then validated with metadata from that same open handle,
/// never a separate path-based `stat`. Symlinks to regular files remain
/// supported. The read itself is capped at `max_bytes + 1`, so growth after
/// metadata collection cannot bypass the limit.
///
/// This is the shared trust-boundary primitive for desktop analysis, agent
/// hashing/YARA scanning, sample retrieval, and future recursive hunts.
pub fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<FileSnapshot> {
    let file = open_nonblocking(path).with_context(|| format!("open {}", path.display()))?;
    read_opened_regular_file_bounded(file, path, max_bytes)
}

/// Reads an already-opened object without consulting its pathname again.
/// The caller owns path resolution; hashing and every later analyzer consume
/// the returned immutable bytes rather than reopening attacker-controlled
/// filesystem state.
pub fn read_opened_regular_file_bounded(
    file: File,
    display_path: &Path,
    max_bytes: u64,
) -> Result<FileSnapshot> {
    let read_limit = max_bytes
        .checked_add(1)
        .context("file read limit must be smaller than u64::MAX")?;
    let metadata = file
        .metadata()
        .with_context(|| format!("fstat {}", display_path.display()))?;

    if !metadata.is_file() {
        bail!(
            "{} is not a regular file, refusing to read it (directories, FIFOs, device nodes,              sockets, and other special files are rejected)",
            display_path.display()
        );
    }
    if metadata.len() > max_bytes {
        bail!(
            "{} is {} bytes, larger than the {} byte limit; not read",
            display_path.display(),
            metadata.len(),
            max_bytes
        );
    }

    let modified_at_open = metadata
        .modified()
        .with_context(|| format!("mtime for {}", display_path.display()))?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", display_path.display()))?;

    if bytes.len() as u64 > max_bytes {
        bail!(
            "{} grew past the {} byte limit while being read; not accepted",
            display_path.display(),
            max_bytes
        );
    }

    Ok(FileSnapshot {
        bytes,
        size_at_open: metadata.len(),
        modified_at_open,
    })
}

/// Hashes a file snapshot using the same hostile-filesystem controls as
/// every other Artemis analysis path.
pub fn compute_hashes(path: &Path) -> Result<HashResult> {
    let snapshot = read_regular_file_bounded(path, MAX_ANALYSIS_BYTES)?;
    Ok(hash_bytes(&snapshot.bytes))
}

/// Hashes an already-in-memory buffer. Callers that also run YARA or other
/// analysis against a file should first use `read_regular_file_bounded`,
/// then hash and inspect this identical byte source.
pub fn hash_bytes(data: &[u8]) -> HashResult {
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    sha256.update(data);
    md5.update(data);
    HashResult {
        sha256: hex::encode(sha256.finalize()),
        md5: hex::encode(md5.finalize()),
    }
}

/// Follows symlinks but prevents a special-file target from blocking the
/// open itself on Unix. Validation always occurs on the returned handle.
#[cfg(unix)]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_content() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();

        let result = compute_hashes(file.path()).unwrap();
        assert_eq!(
            result.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(result.md5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn hash_bytes_matches_file_snapshot() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();

        let snapshot = read_regular_file_bounded(file.path(), 100).unwrap();
        let from_path = compute_hashes(file.path()).unwrap();
        let from_bytes = hash_bytes(&snapshot.bytes);
        assert_eq!(from_bytes, from_path);
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0u8; 10]).unwrap();
        let snapshot = read_regular_file_bounded(file.path(), 10).unwrap();
        assert_eq!(snapshot.bytes.len(), 10);
        assert_eq!(snapshot.size_at_open, 10);
    }

    #[test]
    fn rejects_a_file_over_the_limit_before_reading() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(11).unwrap();
        let error = read_regular_file_bounded(file.path(), 10).unwrap_err();
        assert!(error.to_string().contains("larger than the 10 byte limit"));
    }

    #[test]
    fn rejects_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let error = read_regular_file_bounded(directory.path(), 100).unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn follows_a_symlink_to_a_regular_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"symlinked content").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(file.path(), &link).unwrap();

        let snapshot = read_regular_file_bounded(&link, 100).unwrap();
        assert_eq!(snapshot.bytes, b"symlinked content");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_open_is_nonblocking_and_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("test.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success());

        let start = std::time::Instant::now();
        let error = read_regular_file_bounded(&fifo, 100).unwrap_err();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "opening a FIFO blocked instead of returning promptly"
        );
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn rejects_an_unrepresentable_read_limit() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let error = read_regular_file_bounded(file.path(), u64::MAX).unwrap_err();
        assert!(error.to_string().contains("smaller than u64::MAX"));
    }
}
