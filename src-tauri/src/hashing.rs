use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::path::Path;

pub use nsic_core::hashing::{compute_hashes, HashResult};

/// Hashes a file, reusing the cached result when path + size + mtime match
/// an existing entry so rescans are near-instant. usn is not populated on
/// this platform; it is reserved for the Windows agent, which can key on
/// the USN journal in addition to size and mtime.
pub async fn hash_file_cached(pool: &PgPool, path: &Path) -> Result<HashResult> {
    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    let size = meta.len() as i64;
    let mtime: DateTime<Utc> = meta
        .modified()
        .with_context(|| format!("mtime for {}", path.display()))?
        .into();
    let path_str = path.to_string_lossy().to_string();

    if let Some(cached) = lookup_cache(pool, &path_str, size, mtime).await? {
        return Ok(cached);
    }

    // compute_hashes does synchronous file I/O and CPU-bound digesting; run
    // it on tokio's blocking pool so a large file doesn't stall the worker
    // thread other commands (directory listing, other verdict lookups) share.
    let path_owned = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || compute_hashes(&path_owned))
        .await
        .context("hashing task panicked")??;
    store_cache(pool, &path_str, size, mtime, &result).await?;
    Ok(result)
}

async fn lookup_cache(
    pool: &PgPool,
    path: &str,
    size: i64,
    mtime: DateTime<Utc>,
) -> Result<Option<HashResult>> {
    let row = sqlx::query!(
        "SELECT sha256, md5 FROM hash_cache WHERE path = $1 AND size = $2 AND mtime = $3",
        path,
        size,
        mtime,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| HashResult {
        sha256: r.sha256,
        md5: r.md5.unwrap_or_default(),
    }))
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
