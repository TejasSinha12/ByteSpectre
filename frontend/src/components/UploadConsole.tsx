import { FolderSearch, UploadCloud } from 'lucide-react';
import { useState } from 'react';

interface UploadConsoleProps {
  busy: boolean;
  onUpload: (file: File) => void;
  onPath: (path: string) => void;
}

export function UploadConsole({ busy, onUpload, onPath }: UploadConsoleProps) {
  const [path, setPath] = useState('');

  return (
    <section className="upload-console">
      <label className="drop-target">
        <UploadCloud size={24} />
        <span>{busy ? 'Analyzing artifact...' : 'Upload JAR artifact'}</span>
        <input
          type="file"
          accept=".jar"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) {
              onUpload(file);
            }
          }}
        />
      </label>
      <div className="path-form">
        <FolderSearch size={18} />
        <input
          value={path}
          onChange={(event) => setPath(event.target.value)}
          placeholder="/absolute/path/to/artifact.jar"
          disabled={busy}
        />
        <button type="button" disabled={busy || !path.trim()} onClick={() => onPath(path.trim())}>
          Analyze Path
        </button>
      </div>
    </section>
  );
}

