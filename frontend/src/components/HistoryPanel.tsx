import { Clock3 } from 'lucide-react';
import type { JarAnalysisReport } from '../lib/types';

interface HistoryPanelProps {
  reports: JarAnalysisReport[];
  onSelect: (report: JarAnalysisReport) => void;
  onClear: () => void;
}

export function HistoryPanel({ reports, onSelect, onClear }: HistoryPanelProps) {
  return (
    <section className="panel history-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Local workspace</p>
          <h3>Recent Analyses</h3>
        </div>
        <Clock3 size={20} />
      </div>
      {reports.length === 0 ? (
        <div className="empty-state">Recent analyses will appear here after the first completed scan.</div>
      ) : (
        <>
          <div className="history-list">
            {reports.map((report) => (
              <button type="button" key={report.analysisId} onClick={() => onSelect(report)}>
                <strong>{report.fileName}</strong>
                <span>{report.riskLevel} · {report.riskScore}/100 · {new Date(report.analyzedAt).toLocaleString()}</span>
              </button>
            ))}
          </div>
          <button type="button" className="clear-history" onClick={onClear}>Clear History</button>
        </>
      )}
    </section>
  );
}

