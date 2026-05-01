import { Radar } from 'lucide-react';
import type { AnalysisCapabilities } from '../lib/types';

interface CapabilitiesPanelProps {
  capabilities: AnalysisCapabilities | null;
}

export function CapabilitiesPanel({ capabilities }: CapabilitiesPanelProps) {
  return (
    <section className="panel capabilities-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Engine capabilities</p>
          <h3>{capabilities?.staticEngineVersion ?? 'Static engine'}</h3>
        </div>
        <Radar size={20} />
      </div>
      {!capabilities ? (
        <div className="empty-state">Capability metadata is loading from the backend.</div>
      ) : (
        <div className="capability-groups">
          <CapabilityGroup title="Artifacts" items={capabilities.artifactFamilies} />
          <CapabilityGroup title="Detectors" items={capabilities.detectorFamilies} />
          <CapabilityGroup title="Descriptors" items={capabilities.descriptorFormats} />
        </div>
      )}
    </section>
  );
}

function CapabilityGroup({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <strong>{title}</strong>
      <div>
        {items.slice(0, 12).map((item) => (
          <span key={item}>{item}</span>
        ))}
      </div>
    </div>
  );
}

