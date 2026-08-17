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
///
/// A round-7 review caught that the first version of this guard still had
/// a TOCTOU: it `stat`'d the *path*, decided the target was safe, and only
/// afterward opened the *path* again -- on a live filesystem the directory
/// entry (or a followed symlink's target) can be swapped for a FIFO or
/// device in between, and the bounded read never helps because the open
/// itself can hang before any read is attempted. The fix is to validate
/// the object actually opened, not a pre-open pathname snapshot: `open_regular`
/// opens with `O_NONBLOCK` on Unix (a no-op for a regular file's
/// subsequent reads, but it makes opening a FIFO return immediately
/// instead of blocking for a writer, and a nonblocking open of most other
/// special files also returns promptly rather than hanging), then this
/// function `fstat`s that same open handle -- never a separate path stat
/// -- to decide whether to proceed.
pub async fn hash_and_read_file(pool: &PgPool, path: &Path) -> Result<(HashResult, Vec<u8>)> {
    let path_str = path.to_string_lossy().to_string();

    // Opening, validating, and reading all happen on one blocking-pool
    // task against one open file handle: synchronous file I/O, so it
    // doesn't stall the async worker threads other commands share, and
    // single-handle so there is no path-based recheck anywhere in this
    // sequence for a TOCTOU to hide in.
    let path_owned = path.to_path_buf();
    let (size, mtime, data) = tokio::task::spawn_blocking(move || -> Result<_> {
        let file =
            open_regular(&path_owned).with_context(|| format!("open {}", path_owned.display()))?;

        // fstat on the handle just opened -- the object actually being
        // read, not a separate stat() of the path that could already
        // describe something else by the time it's used.
        let meta = file
            .metadata()
            .with_context(|| format!("fstat {}", path_owned.display()))?;
        if !meta.is_file() {
            anyhow::bail!(
                "{} is not a regular file, refusing to read it for scanning (directories, \
                 FIFOs, device nodes, and other special files are all rejected)",
                path_owned.display()
            );
        }
        if meta.len() > MAX_SCAN_BYTES {
            anyhow::bail!(
                "{} is {} bytes, larger than the {} byte limit for an atomic hash+scan \
                 snapshot; not scanned",
                path_owned.display(),
                meta.len(),
                MAX_SCAN_BYTES
            );
        }
        let size = meta.len() as i64;
        let mtime: DateTime<Utc> = meta
            .modified()
            .with_context(|| format!("mtime for {}", path_owned.display()))?
            .into();

        // `meta.len()` is still a snapshot that can be stale by the time
        // the read below finishes -- a regular file can grow while it's
        // being read -- so the read itself is independently bounded
        // rather than trusting that number alone. `take(MAX_SCAN_BYTES +
        // 1)` (one byte over the limit) lets a file exactly at the limit
        // read in full while still detecting one that has grown past it.
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
        Ok((size, mtime, buf))
    })
    .await
    .context("read task panicked")??;
    let result = hash_bytes(&data);

    store_cache(pool, &path_str, size, mtime, &result).await?;
    Ok((result, data))
}

/// Opens `path` for reading, following symlinks (same as a plain `stat`)
/// but never blocking indefinitely on a special file at the end of that
/// resolution. `O_NONBLOCK` has no effect on a regular file's subsequent
/// reads, so leaving it set for the caller's later `read_to_end` is safe
/// once `fstat` has confirmed the handle really is a regular file.
#[cfg(unix)]
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
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
    ///
    /// A round-7 review pointed out that the *original* fix still stat'd
    /// the path and only rejected based on that stat before a separate
    /// open -- since this FIFO already exists before `hash_and_read_file`
    /// is ever called, that earlier version could also "pass" this test
    /// without ever exercising its own open() call at all (the stat alone
    /// was enough to reject). `open_regular_does_not_block_opening_a_fifo_with_no_writer`
    /// below tests the open() call in isolation to close that gap; this
    /// test remains as the end-to-end confirmation through the real
    /// `hash_and_read_file` path.
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

    /// Round 7 review finding: the previous fix validated a `stat()` of
    /// the *path*, then separately `open()`'d the *path* again -- on a
    /// live filesystem the directory entry (or a followed symlink's
    /// target) can change in between, and a blocking `open()` on a FIFO
    /// with no writer hangs regardless of what any earlier stat said. This
    /// test exercises `open_regular` directly (no DB, no
    /// `hash_and_read_file` wrapper) against a FIFO with no writer and no
    /// data ever queued -- a plain `std::fs::File::open` here would hang
    /// forever; `open_regular` must return immediately because it always
    /// requests `O_NONBLOCK`, and the resulting handle must fstat as a
    /// non-regular file so the caller rejects it without ever reading.
    #[test]
    #[cfg(unix)]
    fn open_regular_does_not_block_opening_a_fifo_with_no_writer() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let fifo_path = dir.path().join("test.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed");

        let start = std::time::Instant::now();
        let file = open_regular(&fifo_path).expect(
            "a nonblocking open of a FIFO with no writer should succeed immediately, not error",
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "open_regular blocked opening a FIFO instead of returning immediately"
        );

        let meta = file.metadata().expect("fstat the open handle");
        assert!(
            !meta.is_file(),
            "a FIFO must not report as a regular file via fstat on the open handle"
        );
    }
}
