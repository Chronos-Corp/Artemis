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
}
