import type { RiskLevel } from '../lib/types';

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export function RiskGauge({ score, level }: RiskGaugeProps) {
  return (
    <section className="risk-panel">
      <div>
        <p className="eyebrow">Risk posture</p>
        <h2>{level}</h2>
      </div>
      <div className="gauge" style={{ '--score': `${score}%` } as React.CSSProperties}>
        <div className="gauge-ring">
          <strong>{score}</strong>
          <span>/100</span>
        </div>
      </div>
    </section>
  );
}

