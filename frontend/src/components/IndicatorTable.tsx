import { ShieldAlert } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { Indicator } from '../lib/types';

interface IndicatorTableProps {
  indicators: Indicator[];
}

export function IndicatorTable({ indicators }: IndicatorTableProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const categories = useMemo(() => Array.from(new Set(indicators.map((indicator) => indicator.category))).sort(), [indicators]);
  const filtered = useMemo(() => {
    const lowered = query.trim().toLowerCase();
    return indicators.filter((indicator) => {
      const matchesCategory = category === 'all' || indicator.category === category;
      const searchable = `${indicator.title} ${indicator.category} ${indicator.evidence} ${indicator.explanation}`.toLowerCase();
      return matchesCategory && (!lowered || searchable.includes(lowered));
    });
  }, [category, indicators, query]);

  return (
    <section className="panel indicators">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Detection explanations</p>
          <h3>Suspicious Indicators</h3>
        </div>
        <ShieldAlert size={20} />
      </div>
      <div className="indicator-controls">
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicators, evidence, or explanation" />
        <select value={category} onChange={(event) => setCategory(event.target.value)}>
          <option value="all">All categories</option>
          {categories.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
      </div>
      <div className="table">
        {filtered.length === 0 ? (
          <div className="empty-state">{indicators.length === 0 ? 'No high-confidence indicators in the current static ruleset.' : 'No indicators match the current filters.'}</div>
        ) : (
          filtered.map((indicator) => (
            <article className="table-row" key={indicator.id}>
              <div>
                <strong>{indicator.title}</strong>
                <span>{indicator.category}</span>
              </div>
              <p>{indicator.explanation}</p>
              <code>{indicator.evidence}</code>
              <div className="indicator-score">
                <b>S{indicator.severity}</b>
                <span>{indicator.confidence}%</span>
              </div>
            </article>
          ))
        )}
      </div>
    </section>
  );
}
