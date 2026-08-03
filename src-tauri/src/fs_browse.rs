use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::Path;

use crate::models::FileEntry;

/// Lists the immediate contents of a directory for the file manager view.
/// Entries that error on stat (permission denied, broken symlink, vanished
/// mid-listing) are skipped rather than aborting the whole listing.
pub async fn list_dir(path: &Path) -> Result<Vec<FileEntry>> {
    let mut read_dir = tokio::fs::read_dir(path)
        .await
        .with_context(|| format!("reading directory {}", path.display()))?;

    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        let modified: Option<DateTime<Utc>> = meta.modified().ok().map(Into::into);
        entries.push(FileEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            path: entry.path().to_string_lossy().to_string(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified,
        });
    }

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(entries)
}
