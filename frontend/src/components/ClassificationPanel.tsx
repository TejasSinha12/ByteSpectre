import { Boxes, Gamepad2 } from 'lucide-react';
import type { ArtifactClassification } from '../lib/types';

interface ClassificationPanelProps {
  classifications: ArtifactClassification[];
}

export function ClassificationPanel({ classifications }: ClassificationPanelProps) {
  return (
    <section className="panel classification-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Artifact classification</p>
          <h3>JAR Family Detection</h3>
        </div>
        <Gamepad2 size={20} />
      </div>
      <div className="classification-list">
        {classifications.map((classification) => (
          <article key={classification.id}>
            <div className="classification-title">
              <Boxes size={16} />
              <div>
                <strong>{classification.label}</strong>
                <span>{classification.family}</span>
              </div>
              <b>{classification.confidence}%</b>
            </div>
            <p>{classification.explanation}</p>
            <div className="evidence-stack">
              {classification.evidence.slice(0, 3).map((item) => (
                <code key={item}>{item}</code>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

