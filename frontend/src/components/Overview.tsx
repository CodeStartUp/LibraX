import { api } from '../api';
import { useAsync } from '../hooks';
import type { IncidentSummary } from '../types';
import { Empty, ErrorBanner, Loading, Metric, Panel, num, riskTone } from './common';

export function Overview({ onOpen }: { onOpen: (id: string) => void }) {
  // Polled, because the simulator keeps pushing telemetry.
  const dashboard = useAsync(() => api.dashboard(), [], 5000);
  const incidents = useAsync(() => api.incidents(), [], 5000);

  if (dashboard.error && !dashboard.data) {
    return (
      <ErrorBanner
        message={dashboard.error}
        hint="Is the API running? Try `docker compose up --build`, or check http://localhost:8080/api/v1/health"
      />
    );
  }
  if (!dashboard.data) {
    return <Loading what="SOC overview" />;
  }

  const d = dashboard.data;

  return (
    <div>
      <div className="grid cols-4" style={{ marginBottom: 12 }}>
        <Metric
          label="Estate"
          value={num(d.endpoints)}
          sub={`endpoints across ${d.hospitals} hospital campuses`}
        />
        <Metric
          label="Events processed"
          value={num(d.events_received)}
          sub={`${num(d.events_per_minute)} per minute · ${num(d.events_rejected)} rejected`}
        />
        <Metric
          label="Detections"
          value={num(d.signals_total)}
          sub={`${d.signals_by_severity.critical} critical · ${d.signals_by_severity.high} high · ${d.signals_by_severity.low} low-grade`}
        />
        <Metric
          label="Incidents"
          value={num(d.incidents_total)}
          sub={`${d.incidents_critical} critical`}
          tone={d.incidents_critical > 0 ? 'critical' : undefined}
        />
      </div>

      <Panel
        title="Alert reduction"
        aside={
          d.reduction.events_per_incident ? (
            <span className="faint mono" style={{ fontSize: 10 }}>
              {num(d.reduction.events_per_incident)} events per surfaced incident
            </span>
          ) : undefined
        }
      >
        <div className="funnel">
          <FunnelStep n={d.reduction.events} what="raw events" />
          <FunnelStep n={d.reduction.signals} what="detections" />
          <FunnelStep n={d.reduction.incidents} what="incidents" />
          <FunnelStep n={d.reduction.critical_incidents} what="critical" final />
        </div>
        <div className="faint" style={{ marginTop: 8, fontSize: 11.5 }}>
          A tier-1 analyst would have to triage the first number. LibraX asks them to look at the
          last one. Every figure here is measured from what the pipeline processed, not configured.
        </div>
      </Panel>

      <Panel
        title="Incident queue"
        flush
        aside={
          <span className="faint mono" style={{ fontSize: 10 }}>
            highest risk first
          </span>
        }
      >
        {incidents.data && incidents.data.incidents.length > 0 ? (
          <IncidentTable incidents={incidents.data.incidents} onOpen={onOpen} />
        ) : incidents.loading ? (
          <Loading what="incidents" />
        ) : (
          <Empty what="No incidents. Telemetry is being processed but nothing has correlated into a case." />
        )}
      </Panel>

      <div className="grid cols-2">
        <Panel title="Telemetry sources">
          <div className="grid cols-3" style={{ gap: 8 }}>
            <Metric label="Healthy" value={d.sources_healthy} />
            <Metric
              label="Warning"
              value={d.sources_warning}
              tone={d.sources_warning > 0 ? 'medium' : undefined}
            />
            <Metric
              label="Blind spot"
              value={d.sources_blind_spot}
              tone={d.sources_blind_spot > 0 ? 'critical' : undefined}
            />
          </div>
          <div style={{ marginTop: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
              <span className="dim">EDR fleet coverage</span>
              <span className="mono">{d.edr_coverage_percent.toFixed(1)}%</span>
            </div>
            <div className="bar" style={{ marginTop: 3 }}>
              <span
                style={{
                  width: `${d.edr_coverage_percent}%`,
                  background: d.edr_coverage_percent < 95 ? 'var(--medium)' : 'var(--low)',
                }}
              />
            </div>
            <div className="faint" style={{ marginTop: 5, fontSize: 11.5 }}>
              Activity on the {num(d.endpoints - Math.round((d.edr_coverage_percent / 100) * d.endpoints))}{' '}
              endpoints without an agent would not appear in any investigation.
            </div>
          </div>
        </Panel>

        <Panel title="Highest priority">
          {d.top_incident ? (
            <div>
              <div className="mono faint" style={{ fontSize: 11 }}>
                {d.top_incident.incident_id}
              </div>
              <div style={{ fontSize: 16, fontWeight: 600, margin: '2px 0 8px' }}>
                {d.top_incident.title}
              </div>
              <div
                className={`mono sev-${riskTone(d.top_incident.overall_risk)}`}
                style={{ fontSize: 34, fontWeight: 600, lineHeight: 1 }}
              >
                {num(d.top_incident.overall_risk)}
                <span className="faint" style={{ fontSize: 14 }}>
                  /100
                </span>
              </div>
              <button
                className="btn"
                style={{ marginTop: 10 }}
                onClick={() => onOpen(d.top_incident!.incident_id)}
              >
                Investigate →
              </button>
            </div>
          ) : (
            <Empty what="Nothing prioritised yet" />
          )}
        </Panel>
      </div>
    </div>
  );
}

function FunnelStep({ n, what, final }: { n: number; what: string; final?: boolean }) {
  return (
    <div className={final ? 'funnel-step final' : 'funnel-step'}>
      <div className="n">{num(n)}</div>
      <div className="what">{what}</div>
    </div>
  );
}

export function IncidentTable({
  incidents,
  onOpen,
}: {
  incidents: IncidentSummary[];
  onOpen: (id: string) => void;
}) {
  return (
    <table className="data">
      <thead>
        <tr>
          <th style={{ width: 92 }}>ID</th>
          <th>Incident</th>
          <th className="right" style={{ width: 58 }}>
            Risk
          </th>
          <th className="right" style={{ width: 58 }}>
            Conf
          </th>
          <th className="right" style={{ width: 58 }}>
            Impact
          </th>
          <th style={{ width: 84 }}>Blast</th>
          <th className="right" style={{ width: 62 }}>
            Signals
          </th>
          <th style={{ width: 70 }}>Duration</th>
          <th>ATT&CK stages</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((inc) => (
          <tr className="clickable" key={inc.incident_id} onClick={() => onOpen(inc.incident_id)}>
            <td className="mono">{inc.incident_id}</td>
            <td>
              <span className={`tag sev-${inc.severity}`} style={{ marginRight: 7 }}>
                {inc.severity}
              </span>
              {inc.title}
            </td>
            <td className={`right mono sev-${riskTone(inc.overall_risk)}`}>
              {num(inc.overall_risk)}
            </td>
            <td className="right mono dim">{num(inc.threat_confidence)}</td>
            <td className="right mono dim">{num(inc.business_impact)}</td>
            <td>
              <span className={`tag sev-${inc.blast_radius_level}`}>{inc.blast_radius_level}</span>
            </td>
            <td className="right mono">{inc.signal_count}</td>
            <td className="mono dim">{inc.duration_minutes}m</td>
            <td className="faint" style={{ fontSize: 11 }}>
              {inc.tactics.length > 0 ? inc.tactics.join(' → ') : 'none mapped'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
