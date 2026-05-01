import { FileArchive, Network, ShieldCheck, Sparkles } from 'lucide-react';

export function EmptyWorkbench() {
  const steps = [
    { icon: FileArchive, title: 'Load artifact', text: 'Upload a JAR or analyze a local path.' },
    { icon: ShieldCheck, title: 'Review detections', text: 'Inspect indicators, confidence, and evidence.' },
    { icon: Network, title: 'Trace structure', text: 'Use graph and descriptor panels for context.' },
    { icon: Sparkles, title: 'Export report', text: 'Save JSON or Markdown for your notes.' }
  ];

  return (
    <section className="empty-workbench">
      {steps.map((step) => (
        <article key={step.title}>
          <step.icon size={20} />
          <strong>{step.title}</strong>
          <span>{step.text}</span>
        </article>
      ))}
    </section>
  );
}

