import { Fingerprint, Gauge, PackageSearch, ShieldAlert } from 'lucide-react';
import type { JarAnalysisReport } from '../lib/types';

interface ReportStatusStripProps {
  report: JarAnalysisReport;
}

export function ReportStatusStrip({ report }: ReportStatusStripProps) {
  return (
    <section className="status-strip">
      <Item icon={Gauge} label="Risk" value={`${report.riskLevel} · ${report.riskScore}/100`} />
      <Item icon={ShieldAlert} label="Indicators" value={String(report.indicators.length)} />
      <Item icon={PackageSearch} label="Families" value={String(report.artifactClassifications.length)} />
      <Item icon={Fingerprint} label="SHA-256" value={report.sha256.slice(0, 18)} />
    </section>
  );
}

function Item({ icon: Icon, label, value }: { icon: typeof Gauge; label: string; value: string }) {
  return (
    <article>
      <Icon size={17} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </article>
  );
}

