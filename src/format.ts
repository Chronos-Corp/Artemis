export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toLocaleString();
}

// Short, relative form ("18 minutes ago", "11 days ago") for the intel
// freshness display -- an analyst scanning a list of sources for "which
// one has gone stale" is better served by relative age than an absolute
// timestamp they'd have to mentally diff against now. formatDate above
// remains the absolute-timestamp formatter used everywhere else
// (provenance first/last-seen), which is what those need instead.
export function formatRelativeTime(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "never";
  const diffMinutes = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
  if (diffMinutes < 1) return "just now";
  if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes === 1 ? "" : "s"} ago`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
  const diffDays = Math.round(diffHours / 24);
  return `${diffDays} day${diffDays === 1 ? "" : "s"} ago`;
}

export function pathSeparator(path: string): string {
  return path.includes("\\") && !path.includes("/") ? "\\" : "/";
}

const WINDOWS_DRIVE_ROOT = /^[A-Za-z]:$/;

export function parentPath(path: string): string {
  const sep = pathSeparator(path);
  const trimmed = path.endsWith(sep) ? path.slice(0, -1) : path;

  // Already at a drive root (e.g. "C:\"); there is nowhere higher to go.
  if (sep === "\\" && WINDOWS_DRIVE_ROOT.test(trimmed)) {
    return `${trimmed}${sep}`;
  }

  const idx = trimmed.lastIndexOf(sep);
  if (idx <= 0) return sep;

  // Parent of "C:\Users" is the drive root "C:\", not the bare "C:".
  if (sep === "\\" && idx === 2 && WINDOWS_DRIVE_ROOT.test(trimmed.slice(0, 2))) {
    return trimmed.slice(0, idx + 1);
  }
  return trimmed.slice(0, idx);
}

export function pathSegments(path: string): { label: string; path: string }[] {
  const sep = pathSeparator(path);
  const parts = path.split(sep).filter(Boolean);
  const segments: { label: string; path: string }[] = [];
  const isDriveRoot = sep === "\\" && WINDOWS_DRIVE_ROOT.test(parts[0] ?? "");
  let acc = path.startsWith(sep) ? sep : "";
  parts.forEach((part, i) => {
    if (i === 0 && isDriveRoot) {
      // "C:" is a root by itself; don't prepend a leading separator.
      acc = `${part}${sep}`;
    } else {
      acc = acc.endsWith(sep) ? `${acc}${part}` : `${acc}${sep}${part}`;
    }
    segments.push({ label: part, path: acc });
  });
  return segments;
}
