import { Boxes } from 'lucide-react';
import type { AssetFinding } from '../lib/types';

interface AssetIntelProps {
  findings: AssetFinding[];
}

export function AssetIntel({ findings }: AssetIntelProps) {
  return (
    <section className="panel asset-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Translation and asset intelligence</p>
          <h3>Capability Signals</h3>
        </div>
        <Boxes size={20} />
      </div>
      <div className="asset-list">
        {findings.length === 0 ? (
          <div className="empty-state">No suspicious asset or translation naming detected.</div>
        ) : (
          findings.slice(0, 8).map((finding) => (
            <article key={`${finding.path}-${finding.signal}`}>
              <strong>{finding.signal}</strong>
              <span>{finding.path}</span>
              <p>{finding.explanation}</p>
            </article>
          ))
        )}
      </div>
    </section>
  );
}

