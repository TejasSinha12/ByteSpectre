import { ShieldAlert } from 'lucide-react';
import type { Indicator } from '../lib/types';

interface IndicatorTableProps {
  indicators: Indicator[];
}

export function IndicatorTable({ indicators }: IndicatorTableProps) {
  return (
    <section className="panel indicators">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Detection explanations</p>
          <h3>Suspicious Indicators</h3>
        </div>
        <ShieldAlert size={20} />
      </div>
      <div className="table">
        {indicators.length === 0 ? (
          <div className="empty-state">No high-confidence indicators in the current static ruleset.</div>
        ) : (
          indicators.map((indicator) => (
            <article className="table-row" key={indicator.id}>
              <div>
                <strong>{indicator.title}</strong>
                <span>{indicator.category}</span>
              </div>
              <p>{indicator.explanation}</p>
              <code>{indicator.evidence}</code>
              <b>{indicator.severity}</b>
            </article>
          ))
        )}
      </div>
    </section>
  );
}

