use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::io::Read as _;
use std::path::Path;

pub use nsic_core::hashing::{hash_bytes, HashResult};

/// Hard cap on how much of a file this will read into memory for an
/// atomic hash+scan snapshot. A round-6 review caught that the original
/// version of this function had no such bound at all: `fs_browse::list_dir`
/// only exposes `is_dir`, so *every* non-directory path the file browser
/// shows -- a multi-gigabyte VM disk image, a live database file -- was
/// reachable here and would be read whole into a `Vec<u8>` on a single
/// click. 256 MiB comfortably covers the executables, scripts, and
/// documents Phase 0's local triage is actually for, while keeping one
/// errant click bounded rather than a potential multi-gigabyte allocation.
/// Larger files are reported as a clear, immediate error rather than an
/// OOM or an indefinite hang -- see the two checks below.
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Reads a file's full contents exactly once and returns them alongside
/// the computed hash, so a caller that also needs to YARA-scan the same
/// content (see `verdict::resolve`) does so against the identical byte
/// source instead of opening the file twice -- a review caught that two
/// separate reads (one to hash, one to scan) can observe different
/// content if the file changes in between, silently binding a YARA hit's
/// persisted `detection_detects_indicator` edge to the wrong hash. Mirrors
/// the pattern `nsic_core::hashing::hash_bytes`'s doc comment describes
/// and `crates/agent/src/main.rs` already follows (`std::fs::read` once,
/// then `hash_bytes` and `scan_bytes` on the same buffer).
///
/// Deliberately does not short-circuit on a `hash_cache` hit the way the
/// since-removed `hash_file_cached` did: a cached hash paired with a
/// *fresh* separate YARA read is exactly the race this function exists to
/// close, so every call reads and hashes the current bytes. Still records
/// the result in the same path+size+mtime cache table other tooling may
/// read from, but purely as a side effect, never as a trust source for
/// this call.
///
/// Refuses to read two categories of path a round-6 review pointed out
/// were both reachable and both unsafe to hand to `std::fs::read`
/// unconditionally: anything that isn't a regular file (a FIFO can block
/// a read indefinitely waiting for a writer that may never come; a
/// character device can return far more data than `len()` ever reported,
/// e.g. `/dev/zero`, which stats at 0 bytes but reads forever), and
/// anything larger than `MAX_SCAN_BYTES`.
pub async fn hash_and_read_file(pool: &PgPool, path: &Path) -> Result<(HashResult, Vec<u8>)> {
    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;

    if !meta.is_file() {
        anyhow::bail!(
            "{} is not a regular file, refusing to read it for scanning (directories, FIFOs, \
             device nodes, and other special files are all rejected)",
            path.display()
        );
    }
    if meta.len() > MAX_SCAN_BYTES {
        anyhow::bail!(
            "{} is {} bytes, larger than the {} byte limit for an atomic hash+scan snapshot; \
             not scanned",
            path.display(),
            meta.len(),
            MAX_SCAN_BYTES
        );
    }

    let size = meta.len() as i64;
    let mtime: DateTime<Utc> = meta
        .modified()
        .with_context(|| format!("mtime for {}", path.display()))?
        .into();
    let path_str = path.to_string_lossy().to_string();

    // Read and hash on tokio's blocking pool: synchronous file I/O and
    // CPU-bound digesting, so a large file doesn't stall the worker thread
    // other commands (directory listing, other verdict lookups) share.
    let path_owned = path.to_path_buf();
    let data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        // `meta.len()` above is a stat() snapshot that can be stale by the
        // time this actually runs -- a regular file can grow between the
        // two -- so the read itself is independently bounded rather than
        // trusting that earlier number alone. `take(MAX_SCAN_BYTES + 1)`
        // (one byte over the limit) lets a file exactly at the limit read
        // in full while still detecting one that has grown past it.
        let file = std::fs::File::open(&path_owned)
            .with_context(|| format!("open {}", path_owned.display()))?;
        let mut buf = Vec::new();
        file.take(MAX_SCAN_BYTES + 1)
            .read_to_end(&mut buf)
            .with_context(|| format!("read {}", path_owned.display()))?;
        if buf.len() as u64 > MAX_SCAN_BYTES {
            anyhow::bail!(
                "{} grew past the {} byte scan limit while being read; not scanned",
                path_owned.display(),
                MAX_SCAN_BYTES
            );
        }
        Ok(buf)
    })
    .await
    .context("read task panicked")??;
    let result = hash_bytes(&data);

    store_cache(pool, &path_str, size, mtime, &result).await?;
    Ok((result, data))
}

async fn store_cache(
    pool: &PgPool,
    path: &str,
    size: i64,
    mtime: DateTime<Utc>,
    result: &HashResult,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO hash_cache (path, size, mtime, sha256, md5)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (path, size, mtime) DO UPDATE SET
            sha256 = EXCLUDED.sha256,
            md5 = EXCLUDED.md5,
            computed_at = now()
        "#,
        path,
        size,
        mtime,
        result.sha256,
        result.md5,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The whole point of `hash_and_read_file`: the hash and the returned
    /// bytes must always describe each other by construction (one read,
    /// hash the buffer), not by a caller trusting two separate reads
    /// happened to observe the same content -- see the function's doc
    /// comment for the race a review caught in the two-read version this
    /// replaced.
    #[tokio::test]
    #[ignore]
    async fn hash_and_read_file_returns_the_hash_of_the_exact_bytes_it_returns() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let marker = uuid::Uuid::new_v4();
        let content = format!("hash and read file test content {marker}");
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let (hash, data) = hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash and read file");

        assert_eq!(data, content.as_bytes());
        assert_eq!(hash_bytes(&data).sha256, hash.sha256);
        assert_eq!(hash_bytes(&data).md5, hash.md5);

        // Rewriting the file *after* the read must not retroactively
        // change what was already read and hashed -- the returned buffer
        // is a true snapshot, not a handle that could observe a later
        // write, which is what made the old two-open-two-read version
        // racy in the first place.
        tmp.write_all(b"more bytes appended after the read")
            .unwrap();
        tmp.flush().unwrap();
        assert_eq!(
            data,
            content.as_bytes(),
            "a buffer already returned must not be affected by a later write to the file"
        );
    }

    /// Round 6 review finding: an oversized file must be rejected before
    /// any large allocation happens, not read whole into memory. Uses
    /// `set_len` to create a sparse file that reports a huge size without
    /// this test actually writing (or this function actually allocating)
    /// that many real bytes -- if the size guard didn't fire before the
    /// read, this test would itself attempt a multi-gigabyte allocation.
    #[tokio::test]
    #[ignore]
    async fn a_file_larger_than_the_scan_limit_is_rejected_without_being_read() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path())
            .unwrap();
        file.set_len(MAX_SCAN_BYTES + 1024).expect("sparse-extend");
        drop(file);

        let err = hash_and_read_file(&pool, tmp.path())
            .await
            .expect_err("a file over the scan limit must be rejected, not read");
        assert!(
            err.to_string().contains("byte limit"),
            "expected a size-limit error, got: {err}"
        );
    }

    /// Round 6 review finding: a FIFO can block a read indefinitely
    /// waiting for a writer that may never come -- `fs_browse::list_dir`
    /// only exposes `is_dir`, so a FIFO on disk was otherwise a reachable,
    /// hang-forever input to this function. Confirms the rejection happens
    /// before any read is attempted (this test would hang forever on its
    /// own `open`+`read` otherwise, since nothing here ever writes to the
    /// FIFO).
    #[tokio::test]
    #[ignore]
    #[cfg(unix)]
    async fn a_fifo_is_rejected_without_blocking() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let dir = tempfile::tempdir().expect("create temp dir");
        let fifo_path = dir.path().join("test.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            hash_and_read_file(&pool, &fifo_path),
        )
        .await
        .expect("hash_and_read_file must return promptly, not hang waiting on the FIFO");
        let err = result.expect_err("a FIFO must be rejected, not read");
        assert!(
            err.to_string().contains("not a regular file"),
            "expected a not-a-regular-file error, got: {err}"
        );
    }
}
