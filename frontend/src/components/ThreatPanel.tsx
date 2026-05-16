import { DependencyArtifact, EndpointFinding, JarAnalysisReport } from '../lib/types';
import { ExternalLink, PackageSearch } from 'lucide-react';
import { useMemo, useState } from 'react';

function sortEndpoints(a: EndpointFinding, b: EndpointFinding) {
  if (a.confidence !== b.confidence) return b.confidence - a.confidence;
  return a.value.localeCompare(b.value);
}

function sortDeps(a: DependencyArtifact, b: DependencyArtifact) {
  if (a.source !== b.source) return a.source.localeCompare(b.source);
  return a.name.localeCompare(b.name);
}

export function ThreatPanel({ report }: { report: JarAnalysisReport }) {
  const [query, setQuery] = useState('');

  const endpoints = useMemo(() => {
    const items = report.endpointFindings ?? [];
    const filtered = query
      ? items.filter((item) => (item.kind + ' ' + item.value).toLowerCase().includes(query.toLowerCase()))
      : items;
    return [...filtered].sort(sortEndpoints).slice(0, 200);
  }, [report.endpointFindings, query]);

  const dependencies = useMemo(() => {
    const items = report.dependencies ?? [];
    const filtered = query
      ? items.filter((item) => (item.name + ' ' + item.version + ' ' + item.path).toLowerCase().includes(query.toLowerCase()))
      : items;
    return [...filtered].sort(sortDeps).slice(0, 250);
  }, [report.dependencies, query]);

  return (
    <section className="panel threat-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Generic JVM threat surface</p>
          <h3>Endpoints and Dependencies</h3>
        </div>
        <PackageSearch size={20} />
      </div>

      <div className="threat-toolbar">
        <label className="threat-search">
          <span className="sr-only">Search endpoints and dependencies</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search URLs, IPs, webhooks, libraries..."
            spellCheck={false}
          />
        </label>
      </div>

      <div className="threat-grid">
        <section className="threat-block">
          <div className="threat-block__header">
            <h4>External Endpoints</h4>
            <span>{endpoints.length}</span>
          </div>
          {endpoints.length === 0 ? (
            <div className="hint-box">No URLs/IPs/webhooks were detected in static strings.</div>
          ) : (
            <div className="threat-list">
              {endpoints.map((item) => (
                <div key={`${item.kind}:${item.value}`} className="threat-row">
                  <div className="threat-row__meta">
                    <span className="chip">{item.kind}</span>
                    <span className="confidence">{item.confidence}%</span>
                  </div>
                  <div className="threat-row__value" title={item.value}>
                    {item.value}
                  </div>
                  {item.kind === 'url' || item.kind === 'discord-webhook' ? (
                    <a className="icon-link" href={item.value} target="_blank" rel="noreferrer" title="Open in browser">
                      <ExternalLink size={16} />
                    </a>
                  ) : (
                    <span className="icon-link disabled" aria-hidden="true">
                      <ExternalLink size={16} />
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="threat-block">
          <div className="threat-block__header">
            <h4>Embedded Dependencies</h4>
            <span>{dependencies.length}</span>
          </div>
          {dependencies.length === 0 ? (
            <div className="hint-box">No embedded libraries or Maven metadata were detected.</div>
          ) : (
            <div className="threat-list">
              {dependencies.map((item) => (
                <div key={`${item.source}:${item.path}`} className="threat-row">
                  <div className="threat-row__meta">
                    <span className="chip">{item.source}</span>
                    <span className="confidence">{item.version || 'unknown'}</span>
                  </div>
                  <div className="threat-row__value" title={item.path}>
                    {item.name}
                  </div>
                  <span className="threat-row__aux">{Math.max(0, item.sizeBytes).toLocaleString()} bytes</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

