import { BookOpen, ExternalLink, Shield } from 'lucide-react';

export function DocsPage() {
  return (
    <section className="docs-page">
      <header>
        <div className="docs-title">
          <Shield size={28} />
          <div>
            <p className="eyebrow">Documentation</p>
            <h1>ByteSpectre Docs</h1>
          </div>
        </div>
        <p className="docs-lead">
          ByteSpectre is a JVM reverse engineering and security analysis workbench. Use the static engine to triage artifacts, then
          iterate toward runtime sandboxing and AI-assisted classification.
        </p>
      </header>

      <div className="docs-grid">
        <article>
          <h2><BookOpen size={18} /> Static Analysis</h2>
          <p>Upload a JAR or analyze a local path. ByteSpectre extracts bytecode facts, assets, descriptors, and indicators with explainable evidence.</p>
          <ul>
            <li>Indicators include severity and confidence.</li>
            <li>Artifact classification identifies mod/plugin/client families.</li>
            <li>Descriptor metadata is extracted for quick inspection.</li>
          </ul>
        </article>

        <article>
          <h2><BookOpen size={18} /> Decompile & Export</h2>
          <p>Use the export actions to download reports and a decompiled source ZIP.</p>
          <ul>
            <li>Export JSON and Markdown reports.</li>
            <li>Decompile ZIP uses CFR and writes sources under <code>decompiled/</code>.</li>
            <li>Deobfuscation mode applies identifier cleanup and duplicate-member renaming for readability.</li>
          </ul>
        </article>

        <article>
          <h2><BookOpen size={18} /> Runtime Sandbox (Planned)</h2>
          <p>The <code>sandbox-agent/</code> module is the runtime telemetry boundary. It will grow into reflection/socket/thread/process tracing.</p>
          <ul>
            <li>Attach via <code>-javaagent</code>.</li>
            <li>Stream events back to the backend over WebSocket.</li>
          </ul>
        </article>

        <article>
          <h2><ExternalLink size={18} /> Project Docs</h2>
          <p>For architecture notes and the dev roadmap, see the repository docs directory.</p>
          <ul>
            <li><code>docs/ARCHITECTURE.md</code></li>
            <li><code>docs/ROADMAP.md</code></li>
            <li><code>docs/DAILY-COMMIT-PLAN.md</code></li>
          </ul>
        </article>
      </div>
    </section>
  );
}

