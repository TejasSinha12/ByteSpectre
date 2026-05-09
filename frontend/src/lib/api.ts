import type { AnalysisCapabilities, JarAnalysisReport } from './types';

export async function analyzeJar(file: File): Promise<JarAnalysisReport> {
  const form = new FormData();
  form.append('file', file);

  const response = await fetch('/api/analysis/jar', {
    method: 'POST',
    body: form
  });

  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }

  return response.json();
}

export async function analyzeJarPath(path: string): Promise<JarAnalysisReport> {
  const params = new URLSearchParams({ path });
  const response = await fetch(`/api/analysis/jar/path?${params.toString()}`, {
    method: 'POST'
  });

  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }

  return response.json();
}

export async function fetchCapabilities(): Promise<AnalysisCapabilities> {
  const response = await fetch('/api/analysis/capabilities');

  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }

  return response.json();
}

export async function downloadDecompileZipFromUpload(file: File, deobfuscate: boolean) {
  const form = new FormData();
  form.append('file', file);
  const params = new URLSearchParams({ deobfuscate: String(deobfuscate) });
  const response = await fetch(`/api/analysis/jar/decompile?${params.toString()}`, {
    method: 'POST',
    body: form
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
  await downloadBlob(response, deobfuscate ? 'deobf.zip' : 'decompile.zip');
}

export async function downloadDecompileZipFromPath(path: string, deobfuscate: boolean) {
  const params = new URLSearchParams({ path, deobfuscate: String(deobfuscate) });
  const response = await fetch(`/api/analysis/jar/path/decompile?${params.toString()}`, {
    method: 'POST'
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
  await downloadBlob(response, deobfuscate ? 'deobf.zip' : 'decompile.zip');
}

async function downloadBlob(response: Response, fallbackFileName: string) {
  const blob = await response.blob();
  const contentDisposition = response.headers.get('content-disposition') ?? '';
  const match = /filename="([^"]+)"/.exec(contentDisposition);
  const fileName = match?.[1] || fallbackFileName;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function errorMessage(response: Response): Promise<string> {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    const body = await response.json() as { message?: string; error?: string };
    return body.message || body.error || `Request failed with HTTP ${response.status}`;
  }
  const text = await response.text();
  return text || `Request failed with HTTP ${response.status}`;
}
