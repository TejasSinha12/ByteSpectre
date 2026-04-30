import { FileJson } from 'lucide-react';
import type { DescriptorMetadata } from '../lib/types';

interface DescriptorPanelProps {
  descriptors: DescriptorMetadata[];
}

export function DescriptorPanel({ descriptors }: DescriptorPanelProps) {
  return (
    <section className="panel descriptor-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Descriptor intelligence</p>
          <h3>Mod and Plugin Metadata</h3>
        </div>
        <FileJson size={20} />
      </div>
      {descriptors.length === 0 ? (
        <div className="empty-state">No known game or JVM descriptor files were extracted.</div>
      ) : (
        <div className="descriptor-list">
          {descriptors.map((descriptor) => (
            <article key={descriptor.path}>
              <strong>{descriptor.type}</strong>
              <code>{descriptor.path}</code>
              <div className="descriptor-fields">
                {Object.entries(descriptor.fields).slice(0, 8).map(([key, value]) => (
                  <span key={key}>
                    <b>{key}</b>
                    <i>{value}</i>
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

