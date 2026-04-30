import type { JarAnalysisReport } from './types';

export async function analyzeJar(file: File): Promise<JarAnalysisReport> {
  const form = new FormData();
  form.append('file', file);

  const response = await fetch('/api/analysis/jar', {
    method: 'POST',
    body: form
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

export async function analyzeJarPath(path: string): Promise<JarAnalysisReport> {
  const params = new URLSearchParams({ path });
  const response = await fetch(`/api/analysis/jar/path?${params.toString()}`, {
    method: 'POST'
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

