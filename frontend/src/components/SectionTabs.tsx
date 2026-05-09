import { Boxes, Braces, GitBranch, History, Radar, Radio, ShieldAlert } from 'lucide-react';

const sections = [
  { href: '#classification', label: 'Classify', icon: Boxes },
  { href: '#history', label: 'History', icon: History },
  { href: '#capabilities', label: 'Engine', icon: Radar },
  { href: '#indicators', label: 'Indicators', icon: ShieldAlert },
  { href: '#relationships', label: 'Graph', icon: GitBranch },
  { href: '#descriptors', label: 'Metadata', icon: Braces },
  { href: '#channels', label: 'Channels', icon: Radio }
];

export function SectionTabs() {
  return (
    <nav className="section-tabs" aria-label="Analysis sections">
      {sections.map((section) => (
        <a key={section.href} href={section.href}>
          <section.icon size={15} />
          <span>{section.label}</span>
        </a>
      ))}
    </nav>
  );
}
