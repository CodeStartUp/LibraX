import { useState } from 'react';

import { ApiError, api } from '../api';
import { useAsync } from '../hooks';
import type { ResponseAction } from '../types';
import { AttackGraphView } from './AttackGraph';
import { Empty, ErrorBanner, Loading, Panel, StatementList, num, riskTone } from './common';

export function IncidentDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const incident = useAsync(() => api.incident(id), [id]);
  const graph = useAsync(() => api.graph(id), [id]);
  const timeline = useAsync(() => api.timeline(id), [id]);
  const mitre = useAsync(() => api.mitre(id), [id]);
  const briefing = useAsync(() => api.briefing(id), [id]);
  const responses = useAsync(() => api.responses(id), [id]);

  if (incident.loading && !incident.data) {
    return <Loading what={id} />;
  }
  if (incident.error && !incident.data) {
    return <ErrorBanner message={incident.error} />;
  }
  if (!incident.data) {
    return <Empty what="Incident not found" />;
  }

  const inc = incident.data;
  const risk = inc.risk;
  const blast = inc.blast_radius;

  return (
    <div>
      <button className="btn" onClick={onBack} style={{ marginBottom: 10 }}>
        ← Incident queue
      </button>

      <header className="incident-head">
        <div className="id">
          {inc.incident_id} · {inc.status} · {inc.signals.length} correlated detections ·{' '}
          {inc.evidence.length} evidence events
        </div>
        <h1>{inc.title}</h1>

        <div className="scores">
          <div className="score">
            <div className="label">Overall risk</div>
            <div className={`value sev-${riskTone(risk.overall_risk)}`}>
              {num(risk.overall_risk)}
              <span className="faint" style={{ fontSize: 13 }}>
                /100
              </span>
            </div>
          </div>
          <div className="score">
            <div className="label">Threat confidence</div>
            <div className="value">{num(risk.threat_confidence)}%</div>
          </div>
          <div className="score">
            <div className="label">Business impact</div>
            <div className="value">{num(risk.business_impact)}%</div>
          </div>
          <div className="score">
            <div className="label">Blast radius</div>
            <div className={`value sev-${blast.level}`}>{blast.level.toUpperCase()}</div>
          </div>
          <div className="score">
            <div className="label">Duration</div>
            <div className="value">
              {timeline.data ? `${timeline.data.duration_minutes}m` : '—'}
            </div>
          </div>
        </div>
      </header>

      <Panel
        title="Attack graph"
        flush
        aside={
          <span className="faint mono" style={{ fontSize: 10 }}>
            every relationship cites its evidence
          </span>
        }
      >
        {graph.loading && !graph.data ? (
          <Loading what="graph" />
        ) : graph.data ? (
          <AttackGraphView graph={graph.data} evidence={inc.evidence} />
        ) : (
          <ErrorBanner message={graph.error ?? 'graph unavailable'} />
        )}
      </Panel>

      <Panel title="Why did LibraX connect these events?">
        {inc.correlation_reasons.length === 0 ? (
          <Empty what="No shared context was recorded" />
        ) : (
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {inc.correlation_reasons.map((reason, i) => (
              <li key={i} style={{ marginBottom: 3 }}>
                {reason}
              </li>
            ))}
          </ul>
        )}
        <div className="faint" style={{ marginTop: 8, fontSize: 11.5 }}>
          Proximity in time alone does not group detections. Each link above required shared
          context: the same identity, host, address, or a shared evidence event.
        </div>
      </Panel>

      <div className="grid cols-2">
        <Panel title="Risk breakdown">
          <div style={{ marginBottom: 10 }}>
            <ScoreBar label="Threat confidence" value={risk.threat_confidence} />
            <ScoreBar label="Business impact" value={risk.business_impact} />
            <ScoreBar label="Attack progression" value={risk.attack_progression} />
          </div>
          {risk.contributions.map((c, i) => (
            <div className="contribution" key={i}>
              <span className="factor">{c.factor}</span>
              <span className="points">
                {c.points >= 0 ? '+' : ''}
                {c.points.toFixed(1)}
              </span>
              <span className="detail">{c.detail}</span>
            </div>
          ))}
        </Panel>

        <Panel title="Blast radius">
          <div className="grid cols-3" style={{ gap: 8, marginBottom: 10 }}>
            <Count label="Users" value={blast.users} />
            <Count label="Endpoints" value={blast.endpoints} />
            <Count label="Servers" value={blast.servers} />
            <Count label="Critical DBs" value={blast.critical_databases} tone="critical" />
            <Count label="PACS" value={blast.pacs_systems} tone="critical" />
            <Count label="Reachable" value={blast.potentially_reachable} tone="medium" />
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Exposure</th>
                <th className="right">Crit</th>
                <th>Site</th>
              </tr>
            </thead>
            <tbody>
              {blast.assets.map((asset) => (
                <tr key={asset.entity.id} title={asset.reason}>
                  <td className="mono">{asset.entity.name}</td>
                  <td>
                    <span
                      className={`tag ${
                        asset.exposure === 'confirmed'
                          ? 'sev-critical'
                          : asset.exposure === 'reachable'
                            ? 'sev-medium'
                            : 'sev-info'
                      }`}
                    >
                      {asset.exposure}
                    </span>
                  </td>
                  <td className="right mono">{asset.criticality || '—'}</td>
                  <td className="mono faint">{asset.hospital ?? 'external'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="faint" style={{ marginTop: 8, fontSize: 11.5 }}>
            Reachable and potential assets are not compromised. They are what this position would
            allow an operator to attempt next.
          </div>
        </Panel>
      </div>

      <Panel
        title="MITRE ATT&CK progression"
        aside={
          mitre.data ? (
            <span className="faint mono" style={{ fontSize: 10 }}>
              {mitre.data.dataset} v{mitre.data.attack_version} · {mitre.data.observed_stages}/
              {mitre.data.total_stages} stages · score {num(mitre.data.score)}
            </span>
          ) : undefined
        }
      >
        {mitre.data ? (
          <>
            <div className="stages">
              {mitre.data.stages.map((stage, i) => {
                const observed = stage.status === 'observed';
                return (
                  <div className={observed ? 'stage observed' : 'stage'} key={stage.tactic_id}>
                    <div className="n">
                      {String(i + 1).padStart(2, '0')} · {stage.tactic_id}
                    </div>
                    <div className="tactic">{stage.label}</div>
                    {observed ? (
                      stage.techniques.map((t) => (
                        <span className="tech" key={t.technique_id} title={t.rationale}>
                          {t.technique_id}
                        </span>
                      ))
                    ) : (
                      <span className="tech faint">not observed</span>
                    )}
                  </div>
                );
              })}
            </div>

            <table className="data" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Name</th>
                  <th>Tactic</th>
                  <th className="right">Conf</th>
                  <th>Why it was mapped</th>
                </tr>
              </thead>
              <tbody>
                {mitre.data.techniques.map((t) => (
                  <tr key={`${t.technique_id}-${t.tactic}`}>
                    <td className="mono">{t.technique_id}</td>
                    <td>{t.name}</td>
                    <td className="dim">{t.tactic.replace(/_/g, ' ')}</td>
                    <td className="right mono">{(t.confidence * 100).toFixed(0)}%</td>
                    <td className="dim">{t.rationale}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {mitre.data.unmapped.length > 0 ? (
              <div className="banner warn" style={{ marginTop: 10 }}>
                Unmapped: {mitre.data.unmapped.join(', ')}. These were proposed but are not in the
                loaded dataset, so they are shown rather than invented.
              </div>
            ) : null}
          </>
        ) : (
          <Loading what="ATT&CK mapping" />
        )}
      </Panel>

      <div className="grid cols-2">
        <Panel title="Timeline">
          {timeline.data ? (
            <div className="timeline">
              {timeline.data.entries.map((entry) => (
                <div className="timeline-row" key={entry.event_id}>
                  <div className="time">{entry.time}</div>
                  <div className={`marker sev-${entry.severity}`}>
                    <i />
                  </div>
                  <div>
                    <div className="summary">{entry.summary}</div>
                    <div className="meta">
                      {entry.event_id} · {entry.source} · {entry.severity.toUpperCase()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Loading what="timeline" />
          )}
        </Panel>

        <div>
          <Panel title="What has not been confirmed">
            {inc.unknowns.length === 0 ? (
              <Empty what="Nothing outstanding" />
            ) : (
              inc.unknowns.map((unknown, i) => (
                <div className="unknown-item" key={i}>
                  <span>{unknown}</span>
                </div>
              ))
            )}
          </Panel>

          {briefing.data ? (
            <Panel
              title="Analyst briefing"
              aside={
                <span className="faint mono" style={{ fontSize: 10 }}>
                  {briefing.data.generator}
                </span>
              }
            >
              <SubHead>What happened</SubHead>
              <StatementList statements={briefing.data.summary} />
              <SubHead>Why this score</SubHead>
              <StatementList statements={briefing.data.risk_explanation} />
              <SubHead>What supports the correlation</SubHead>
              <StatementList statements={briefing.data.evidence_explanation} />
              <SubHead>What to investigate next</SubHead>
              <StatementList statements={briefing.data.investigation_guidance} />
            </Panel>
          ) : (
            <Panel title="Analyst briefing">
              <Loading what="briefing" />
            </Panel>
          )}
        </div>
      </div>

      <ResponsePanel
        incidentId={id}
        listing={responses.data}
        loading={responses.loading}
        onChanged={responses.reload}
      />
    </div>
  );
}

function SubHead({ children }: { children: string }) {
  return (
    <div
      className="faint"
      style={{
        fontSize: 10,
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        marginTop: 10,
        marginBottom: 2,
        borderBottom: '1px solid var(--border)',
        paddingBottom: 3,
      }}
    >
      {children}
    </div>
  );
}

function ScoreBar({ label, value }: { label: string; value: number }) {
  const tone = riskTone(value);
  return (
    <div style={{ marginBottom: 7 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
        <span className="dim">{label}</span>
        <span className="mono">{num(value)}</span>
      </div>
      <div className="bar" style={{ marginTop: 3 }}>
        <span
          style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: `var(--${tone})` }}
        />
      </div>
    </div>
  );
}

function Count({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div style={{ border: '1px solid var(--border)', padding: '6px 8px' }}>
      <div className="faint" style={{ fontSize: 9.5, letterSpacing: '0.1em' }}>
        {label.toUpperCase()}
      </div>
      <div
        className="mono"
        style={{ fontSize: 18, fontWeight: 600, color: tone ? `var(--${tone})` : undefined }}
      >
        {value}
      </div>
    </div>
  );
}

/// Containment. Destructive actions are refused by the API without an approver,
/// so this panel asks for a name rather than hiding the requirement.
function ResponsePanel(props: {
  incidentId: string;
  listing: import('../types').ResponseListing | null;
  loading: boolean;
  onChanged: () => void;
}) {
  const { incidentId, listing } = props;
  const [approver, setApprover] = useState('analyst.tier2');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ResponseAction>>({});

  const simulate = async (action: ResponseAction) => {
    setBusy(action.action_id);
    setError(null);
    try {
      const outcome = await api.simulate(
        incidentId,
        action.action_id,
        action.requires_approval ? approver : undefined,
      );
      setResults((prev) => ({ ...prev, [action.action_id]: outcome.action }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel
      title="Response"
      aside={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="faint mono" style={{ fontSize: 10 }}>
            APPROVER
          </span>
          <input
            value={approver}
            onChange={(e) => setApprover(e.target.value)}
            className="mono"
            style={{
              background: 'var(--panel-3)',
              border: '1px solid var(--border-bright)',
              color: 'var(--text)',
              padding: '3px 7px',
              fontSize: 11,
              width: 130,
            }}
          />
        </div>
      }
    >
      <div className="banner info">
        Every action here is simulated. LibraX has no live integration with any endpoint, directory
        or firewall, and destructive actions are refused without a named approver.
      </div>

      {listing && listing.playbooks.length > 0 ? (
        <div className="chip-row" style={{ marginBottom: 10 }}>
          {listing.playbooks.map((playbook) => (
            <span className="tag sev-low" key={playbook}>
              {playbook}
            </span>
          ))}
        </div>
      ) : null}

      {error ? <ErrorBanner message={error} /> : null}

      {props.loading && !listing ? (
        <Loading what="playbooks" />
      ) : !listing || listing.actions.length === 0 ? (
        <Empty what="No containment recommended" />
      ) : (
        listing.actions.map((stored) => {
          const action = results[stored.action_id] ?? stored;
          const done = action.status === 'simulated';

          return (
            <div className="action" key={action.action_id}>
              <div className="action-head">
                <span className="kind">{action.kind.replace(/_/g, ' ').toUpperCase()}</span>
                <span className="faint">→</span>
                <span className="target">{action.target.name}</span>
                <span className="tag sev-info">{(action.confidence * 100).toFixed(0)}%</span>
                {action.requires_approval ? (
                  <span className="tag sev-high">approval required</span>
                ) : (
                  <span className="tag sev-low">non-destructive</span>
                )}
                <div style={{ marginLeft: 'auto' }}>
                  <button
                    className={action.requires_approval ? 'btn danger' : 'btn'}
                    disabled={done || busy === action.action_id}
                    onClick={() => void simulate(action)}
                  >
                    {done
                      ? 'Simulated'
                      : busy === action.action_id
                        ? 'Running…'
                        : 'Simulate'}
                  </button>
                </div>
              </div>
              <div className="rationale">{action.rationale}</div>
              {action.result ? <div className="result">{action.result}</div> : null}
            </div>
          );
        })
      )}
    </Panel>
  );
}
