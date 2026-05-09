import { Radio } from 'lucide-react';
import type { JarAnalysisReport } from '../lib/types';

interface ChannelsPanelProps {
  report: JarAnalysisReport;
}

export function ChannelsPanel({ report }: ChannelsPanelProps) {
  const items = report.channelFindings ?? [];
  return (
    <section className="panel channels-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Protocol surface</p>
          <h3>Plugin/Mod Channels</h3>
        </div>
        <Radio size={20} />
      </div>
      {items.length === 0 ? (
        <div className="empty-state">No plugin/mod channel registrations were detected in static bytecode.</div>
      ) : (
        <div className="channels-list">
          {items.slice(0, 20).map((item) => (
            <article key={`${item.system}-${item.direction}-${item.channel}-${item.sourceClass}-${item.sourceMethod}`}>
              <strong>{item.channel}</strong>
              <span>{item.system} · {item.direction}</span>
              <code>{item.sourceClass} :: {item.sourceMethod}</code>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

