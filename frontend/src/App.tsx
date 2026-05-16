import { Activity, BrainCircuit, DatabaseZap, RadioTower, SearchCode } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { AssetIntel } from './components/AssetIntel';
import { CapabilitiesPanel } from './components/CapabilitiesPanel';
import { CategoryChips } from './components/CategoryChips';
import { ClassificationPanel } from './components/ClassificationPanel';
import { ChannelsPanel } from './components/ChannelsPanel';
import { ThreatPanel } from './components/ThreatPanel';
import { DescriptorPanel } from './components/DescriptorPanel';
import { DocsPage } from './components/DocsPage';
import { EmptyWorkbench } from './components/EmptyWorkbench';
import { GraphPreview } from './components/GraphPreview';
import { HistoryPanel } from './components/HistoryPanel';
import { IndicatorTable } from './components/IndicatorTable';
import { LoadingOverlay } from './components/LoadingOverlay';
import { RelationshipGraph } from './components/RelationshipGraph';
import { ReportActions } from './components/ReportActions';
import { ReportStatusStrip } from './components/ReportStatusStrip';
import { RiskGauge } from './components/RiskGauge';
import { SectionTabs } from './components/SectionTabs';
import { UploadConsole } from './components/UploadConsole';
import { analyzeJar, analyzeJarPath, fetchCapabilities } from './lib/api';
import type { AnalysisCapabilities, JarAnalysisReport } from './lib/types';

const initialEvents = [
  'Static engine online',
  'ASM bytecode extractor ready',
  'AI feature vector bridge idle',
  'Sandbox instrumentation queue standing by'
];
const historyKey = 'bytespectre.analysisHistory';

export function App() {
  const [view, setView] = useState<'analysis' | 'docs'>('analysis');
  const [report, setReport] = useState<JarAnalysisReport | null>(null);
  const [history, setHistory] = useState<JarAnalysisReport[]>(() => loadHistory());
  const [capabilities, setCapabilities] = useState<AnalysisCapabilities | null>(null);
  const [sourceFile, setSourceFile] = useState<File | null>(null);
  const [sourcePath, setSourcePath] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState(initialEvents);

  const resourceTotal = useMemo(() => {
    if (!report) {
      return 0;
    }
    return Object.values(report.resourceSummary).reduce((total, value) => total + value, 0);
  }, [report]);

  useEffect(() => {
    fetchCapabilities()
      .then(setCapabilities)
      .catch(() => setCapabilities(null));
  }, []);

  async function runAnalysis(task: () => Promise<JarAnalysisReport>) {
    setBusy(true);
    setError(null);
    setEvents((current) => ['Artifact queued for static triage', ...current].slice(0, 8));
    try {
      const nextReport = await task();
      setReport(nextReport);
      setHistory((current) => saveHistory([nextReport, ...current.filter((item) => item.sha256 !== nextReport.sha256)].slice(0, 8)));
      setEvents((current) => [
        `Analysis ${nextReport.analysisId.slice(0, 8)} completed with ${nextReport.riskLevel} posture`,
        `${nextReport.indicators.length} indicators and ${nextReport.assetFindings.length} asset signals produced`,
        ...current
      ].slice(0, 8));
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Analysis failed';
      setError(message);
      setEvents((current) => [`Analysis failed: ${message}`, ...current].slice(0, 8));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <SearchCode size={26} />
          <div>
            <strong>ByteSpectre</strong>
            <span>JVM Security Workbench</span>
          </div>
        </div>
        <nav>
          <a className={view === 'analysis' ? 'active' : ''} onClick={() => setView('analysis')} role="button" tabIndex={0}><Activity size={18} /> Analysis</a>
          <a className={view === 'docs' ? 'active' : ''} onClick={() => setView('docs')} role="button" tabIndex={0}><DatabaseZap size={18} /> Docs</a>
          <a aria-disabled="true"><BrainCircuit size={18} /> AI Signals</a>
          <a aria-disabled="true"><RadioTower size={18} /> Runtime Sandbox</a>
        </nav>
      </aside>

      <section className="workspace">
        {view === 'docs' ? (
          <DocsPage />
        ) : (
        <>
        <header className="topbar">
          <div>
            <p className="eyebrow">AI-powered Java reverse engineering and security platform</p>
            <h1>JAR Analysis Console</h1>
          </div>
          <div className="status-pill">
            <i />
            Static Engine v1
          </div>
        </header>

        <ReportActions report={report} sourceFile={sourceFile} sourcePath={sourcePath} />

        <UploadConsole
          busy={busy}
          onUpload={(file) => {
            setSourceFile(file);
            setSourcePath(null);
            runAnalysis(() => analyzeJar(file));
          }}
          onPath={(path) => {
            setSourceFile(null);
            setSourcePath(path);
            runAnalysis(() => analyzeJarPath(path));
          }}
        />

        {error && <div className="error-banner">{error}</div>}
        {busy && <LoadingOverlay />}

        <section className="dashboard-grid">
          <RiskGauge score={report?.riskScore ?? 0} level={report?.riskLevel ?? 'LOW'} />
          <section className="panel summary-panel">
            <p className="eyebrow">Analysis summary</p>
            <h3>{report?.fileName ?? 'No artifact loaded'}</h3>
            <p>{report?.summary ?? 'Upload a JAR or analyze a local path to begin static triage.'}</p>
            {report && <CategoryChips categories={report.behaviorCategories} />}
            <div className="summary-metrics">
              <Metric label="Resources" value={resourceTotal} />
              <Metric label="Indicators" value={report?.indicators.length ?? 0} />
              <Metric label="Categories" value={report?.behaviorCategories.length ?? 0} />
            </div>
            {report && <code className="hash-line">SHA-256 {report.sha256}</code>}
          </section>
          <section className="panel event-feed">
            <p className="eyebrow">Realtime event feed</p>
            {events.map((event) => (
              <div key={event} className="event-line">
                <i />
                <span>{event}</span>
              </div>
            ))}
          </section>
        </section>

        {report && <ReportStatusStrip report={report} />}
        {report && <SectionTabs />}
        {!report && <EmptyWorkbench />}

        {report && (
          <section className="analysis-grid">
            <div id="classification"><ClassificationPanel classifications={report.artifactClassifications} /></div>
            <div id="history">
              <HistoryPanel
                reports={history}
                onSelect={(item) => {
                  setReport(item);
                  setEvents((current) => [`Restored ${item.fileName} from local history`, ...current].slice(0, 8));
                }}
                onClear={() => {
                  localStorage.removeItem(historyKey);
                  setHistory([]);
                }}
              />
            </div>
            <div id="capabilities"><CapabilitiesPanel capabilities={capabilities} /></div>
            <div id="indicators" className="wide-panel"><IndicatorTable indicators={report.indicators} /></div>
            <div id="threat" className="wide-panel"><ThreatPanel report={report} /></div>
            <div id="relationships" className="wide-panel"><RelationshipGraph relationships={report.relationships} methodCallEdges={report.methodCallEdges} /></div>
            <div id="descriptors"><DescriptorPanel descriptors={report.descriptorMetadata} /></div>
            <div id="channels"><ChannelsPanel report={report} /></div>
            <GraphPreview packages={report.packages} relationships={report.relationships} methodCallEdges={report.methodCallEdges} />
            <AssetIntel findings={report.assetFindings} />
            <section className="panel ai-panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">AI-assisted detection layer</p>
                  <h3>Feature Vector</h3>
                </div>
                <BrainCircuit size={20} />
              </div>
              <pre>{JSON.stringify(report.aiSignals, null, 2)}</pre>
            </section>
          </section>
        )}
        </>
        )}
      </section>
    </main>
  );
}

function loadHistory(): JarAnalysisReport[] {
  try {
    return JSON.parse(localStorage.getItem(historyKey) ?? '[]') as JarAnalysisReport[];
  } catch {
    return [];
  }
}

function saveHistory(history: JarAnalysisReport[]) {
  localStorage.setItem(historyKey, JSON.stringify(history));
  return history;
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <strong>{value.toLocaleString()}</strong>
      <span>{label}</span>
    </div>
  );
}
