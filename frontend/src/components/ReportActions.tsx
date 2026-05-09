import { Download, FileArchive } from 'lucide-react';
import type { JarAnalysisReport } from '../lib/types';
import { downloadDecompileZipFromPath, downloadDecompileZipFromUpload } from '../lib/api';

interface ReportActionsProps {
  report: JarAnalysisReport | null;
  sourceFile: File | null;
  sourcePath: string | null;
}

export function ReportActions({ report, sourceFile, sourcePath }: ReportActionsProps) {
  return (
    <div className="report-actions">
      <button type="button" disabled={!report} onClick={() => report && downloadJson(report)}>
        <Download size={15} />
        JSON
      </button>
      <button type="button" disabled={!report} onClick={() => report && downloadMarkdown(report)}>
        <Download size={15} />
        Markdown
      </button>
      <button
        type="button"
        disabled={!report || (!sourceFile && !sourcePath)}
        onClick={async () => {
          if (sourceFile) {
            await downloadDecompileZipFromUpload(sourceFile, false);
            return;
          }
          if (sourcePath) {
            await downloadDecompileZipFromPath(sourcePath, false);
          }
        }}
      >
        <FileArchive size={15} />
        Decompile ZIP
      </button>
      <button
        type="button"
        disabled={!report || (!sourceFile && !sourcePath)}
        onClick={async () => {
          if (sourceFile) {
            await downloadDecompileZipFromUpload(sourceFile, true);
            return;
          }
          if (sourcePath) {
            await downloadDecompileZipFromPath(sourcePath, true);
          }
        }}
      >
        <FileArchive size={15} />
        Deobfuscate ZIP
      </button>
    </div>
  );
}

function downloadJson(report: JarAnalysisReport) {
  download(`${safeName(report.fileName)}-bytespectre.json`, JSON.stringify(report, null, 2), 'application/json');
}

function downloadMarkdown(report: JarAnalysisReport) {
  const lines = [
    `# ByteSpectre Report: ${report.fileName}`,
    '',
    `- Risk: ${report.riskLevel} (${report.riskScore}/100)`,
    `- Analysis ID: ${report.analysisId}`,
    `- Analyzed At: ${report.analyzedAt}`,
    '',
    '## Summary',
    report.summary,
    '',
    '## Artifact Classifications',
    ...report.artifactClassifications.map((item) => `- ${item.label} (${item.family}, ${item.confidence}%): ${item.evidence.join(', ')}`),
    '',
    '## Indicators',
    ...report.indicators.map((item) => `- [S${item.severity}/${item.confidence}%] ${item.title}: ${item.explanation}`),
    '',
    '## Descriptor Metadata',
    ...report.descriptorMetadata.map((item) => `- ${item.type}: ${item.path}`)
  ];
  download(`${safeName(report.fileName)}-bytespectre.md`, lines.join('\n'), 'text/markdown');
}

function download(fileName: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

function safeName(value: string) {
  return value.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-|-$/g, '') || 'analysis';
}
