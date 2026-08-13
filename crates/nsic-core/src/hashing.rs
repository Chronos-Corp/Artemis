use anyhow::{Context, Result};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HashResult {
    pub sha256: String,
    pub md5: String,
}

/// Hashes a file's full contents. Pure and DB-free so both the Phase 0
/// desktop app (which layers a Postgres path+size+mtime cache on top; see
/// `src-tauri/src/hashing.rs`) and the Phase 1 agent (which has no local
/// Postgres at all) share the exact same digest computation instead of two
/// implementations drifting apart.
pub fn compute_hashes(path: &Path) -> Result<HashResult> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha256.update(&buf[..n]);
        md5.update(&buf[..n]);
    }
    Ok(HashResult {
        sha256: hex::encode(sha256.finalize()),
        md5: hex::encode(md5.finalize()),
    })
}

/// Hashes an already-in-memory buffer. Exists so a caller that also needs
/// to run something else (e.g. a YARA scan) against the same bytes can
/// read the file exactly once and hash and scan the identical byte
/// source, instead of opening the file twice and risking the two reads
/// observing different content if the file changes in between -- see
/// `YaraEngine::scan_bytes` and `nsic-agent scan`'s use of both together.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_content() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let result = compute_hashes(f.path()).unwrap();
        assert_eq!(
            result.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(result.md5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn hash_bytes_matches_compute_hashes_for_the_same_content() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let from_path = compute_hashes(f.path()).unwrap();
        let from_bytes = hash_bytes(b"hello world");
        assert_eq!(from_bytes.sha256, from_path.sha256);
        assert_eq!(from_bytes.md5, from_path.md5);
    }
}
