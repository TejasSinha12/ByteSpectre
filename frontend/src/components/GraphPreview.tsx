import { GitBranch, Network } from 'lucide-react';
import type { ClassRelationship, MethodCallEdge, PackageSummary } from '../lib/types';

interface GraphPreviewProps {
  packages: PackageSummary[];
  relationships: ClassRelationship[];
  methodCallEdges: MethodCallEdge[];
}

export function GraphPreview({ packages, relationships, methodCallEdges }: GraphPreviewProps) {
  return (
    <section className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Bytecode graph surface</p>
          <h3>Relationship Index</h3>
        </div>
        <GitBranch size={20} />
      </div>
      <div className="graph-grid">
        <Metric label="Packages" value={packages.length} />
        <Metric label="Inheritance edges" value={relationships.length} />
        <Metric label="Interesting calls" value={methodCallEdges.length} />
      </div>
      <div className="package-stack">
        {packages.slice(0, 8).map((item) => (
          <div key={item.name} className="package-row">
            <span>{item.name}</span>
            <div className="bar">
              <i style={{ width: `${Math.min(100, item.classCount * 8)}%` }} />
            </div>
            <b>{item.suspiciousSignalCount}</b>
          </div>
        ))}
      </div>
      <div className="callout">
        <Network size={16} />
        <span>Graph data is returned as API-ready nodes and edges for full zoom/filter/tracing views.</span>
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="metric-tile">
      <strong>{value.toLocaleString()}</strong>
      <span>{label}</span>
    </div>
  );
}

