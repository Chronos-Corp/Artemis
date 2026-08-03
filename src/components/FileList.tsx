import type { FileEntry } from "../types";
import { formatDate, formatSize } from "../format";

interface Props {
  entries: FileEntry[];
  selectedPath: string | null;
  loading: boolean;
  onOpenDir: (path: string) => void;
  onSelectFile: (entry: FileEntry) => void;
}

export function FileList({ entries, selectedPath, loading, onOpenDir, onSelectFile }: Props) {
  if (loading) {
    return <div className="file-list-empty">Loading...</div>;
  }
  if (entries.length === 0) {
    return <div className="file-list-empty">This directory is empty.</div>;
  }

  return (
    <table className="file-list">
      <thead>
        <tr>
          <th>Name</th>
          <th>Size</th>
          <th>Modified</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr
            key={entry.path}
            className={entry.path === selectedPath ? "selected" : ""}
            onDoubleClick={() => (entry.is_dir ? onOpenDir(entry.path) : onSelectFile(entry))}
            onClick={() => !entry.is_dir && onSelectFile(entry)}
          >
            <td>
              <span className="file-icon">{entry.is_dir ? "\u{1F4C1}" : "\u{1F4C4}"}</span>
              {entry.name}
            </td>
            <td>{entry.is_dir ? "-" : formatSize(entry.size)}</td>
            <td>{formatDate(entry.modified)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
