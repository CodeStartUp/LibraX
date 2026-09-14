import type { ReactNode } from 'react';

import type { Severity, Statement } from '../types';

export function Panel(props: {
  title: string;
  children: ReactNode;
  aside?: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{props.title}</h2>
        {props.aside ? <div className="spacer">{props.aside}</div> : null}
      </div>
      <div className={props.flush ? 'panel-body flush' : 'panel-body'}>{props.children}</div>
    </section>
  );
}

export function Metric(props: { label: string; value: ReactNode; sub?: ReactNode; tone?: Severity }) {
  return (
    <div className="metric">
      <div className="label">{props.label}</div>
      <div className={props.tone ? `value sev-${props.tone}` : 'value'}>{props.value}</div>
      {props.sub ? <div className="sub">{props.sub}</div> : null}
    </div>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`tag sev-${severity}`}>{severity}</span>;
}

export function Loading({ what }: { what: string }) {
  return <div className="loading">Loading {what}…</div>;
}

export function Empty({ what }: { what: string }) {
  return <div className="empty">{what}</div>;
}

export function ErrorBanner({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="banner error">
      {message}
      {hint ? <div className="faint" style={{ marginTop: 4 }}>{hint}</div> : null}
    </div>
  );
}

/// Renders a claim with its epistemic status, which is the point of the briefing:
/// the reader must be able to tell a cited fact from a reading of the facts.
export function StatementList({ statements }: { statements: Statement[] }) {
  if (statements.length === 0) {
    return <Empty what="Nothing recorded" />;
  }

  return (
    <div>
      {statements.map((statement, i) => (
        <div className={`statement ${statement.assertion}`} key={i}>
          <div className="label">{statement.label}</div>
          <div>
            {statement.text}
            {statement.evidence_event_ids.length > 0 ? (
              <div className="cites">
                Evidence: {statement.evidence_event_ids.slice(0, 12).join(', ')}
                {statement.evidence_event_ids.length > 12
                  ? ` +${statement.evidence_event_ids.length - 12} more`
                  : ''}
              </div>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function num(value: number, digits = 0): string {
  return value.toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function riskTone(score: number): Severity {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'info';
}
