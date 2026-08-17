use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::path::Path;

pub use nsic_core::hashing::{hash_bytes, HashResult};

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
pub async fn hash_and_read_file(pool: &PgPool, path: &Path) -> Result<(HashResult, Vec<u8>)> {
    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;
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
    let data = tokio::task::spawn_blocking(move || std::fs::read(&path_owned))
        .await
        .context("read task panicked")?
        .with_context(|| format!("read {}", path.display()))?;
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
}
