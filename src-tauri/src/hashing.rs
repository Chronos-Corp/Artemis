use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::path::Path;

pub use nsic_core::hashing::{hash_bytes, HashResult};
use nsic_core::hashing::{
    read_opened_regular_file_bounded, read_regular_file_bounded, FileSnapshot,
    MAX_ANALYSIS_BYTES,
};

/// Reads one hostile-filesystem-safe snapshot, then hashes and returns those
/// exact bytes. The shared `nsic_core` primitive performs nonblocking open
/// on Unix, same-handle regular-file validation, a pre-read size check, and
/// an independently bounded read that detects growth past the limit.
///
/// The desktop-specific responsibility left here is only persisting the
/// snapshot metadata and hashes into its Postgres cache. The cache remains
/// a side effect, never a trust source for this call.
pub async fn hash_and_read_file(pool: &PgPool, path: &Path) -> Result<(HashResult, Vec<u8>)> {
    let path_string = path.to_string_lossy().to_string();
    let path_owned = path.to_path_buf();

    let snapshot = tokio::task::spawn_blocking(move || {
        read_regular_file_bounded(&path_owned, MAX_ANALYSIS_BYTES)
    })
    .await
    .context("read task panicked")??;

    let size = i64::try_from(snapshot.size_at_open)
        .context("opened file size does not fit the desktop cache schema")?;
    let modified: DateTime<Utc> = snapshot.modified_at_open.into();
    let result = hash_bytes(&snapshot.bytes);

    store_cache(pool, &path_string, size, modified, &result).await?;
    Ok((result, snapshot.bytes))
}

pub async fn hash_opened_snapshot(
    pool: &PgPool,
    path: &Path,
    snapshot: FileSnapshot,
) -> Result<(HashResult, Vec<u8>)> {
    let size = i64::try_from(snapshot.size_at_open)
        .context("opened file size does not fit the desktop cache schema")?;
    let modified: DateTime<Utc> = snapshot.modified_at_open.into();
    let result = hash_bytes(&snapshot.bytes);
    store_cache(pool, &path.to_string_lossy(), size, modified, &result).await?;
    Ok((result, snapshot.bytes))
}

pub fn read_opened_snapshot(file: std::fs::File, path: &Path) -> Result<FileSnapshot> {
    read_opened_regular_file_bounded(file, path, MAX_ANALYSIS_BYTES)
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

    #[tokio::test]
    #[ignore]
    async fn desktop_cache_records_the_exact_snapshot_hash() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(b"desktop snapshot content").unwrap();
        file.flush().unwrap();

        let (hash, bytes) = hash_and_read_file(&pool, file.path())
            .await
            .expect("hash and read file");

        assert_eq!(bytes, b"desktop snapshot content");
        assert_eq!(hash, hash_bytes(&bytes));

        let cached: (String, String) = sqlx::query_as(
            "SELECT sha256, md5 FROM hash_cache WHERE path = $1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(file.path().to_string_lossy().as_ref())
        .fetch_one(&pool)
        .await
        .expect("read cached snapshot");

        assert_eq!(cached.0, hash.sha256);
        assert_eq!(cached.1, hash.md5);
    }
}
