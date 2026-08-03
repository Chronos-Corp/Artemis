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
