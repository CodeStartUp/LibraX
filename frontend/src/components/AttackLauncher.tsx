import { useState } from 'react';

import { api } from '../api';
import { useAsync } from '../hooks';
import type { AttackKind, AttackRun } from '../types';
import { ErrorBanner, Loading, Panel, SeverityTag } from './common';

/// Playback speeds offered to the analyst.
///
/// A real intrusion takes half an hour, which nobody watches. Accelerating it
/// keeps the arrival *order* and the gaps between stages, which is what
/// correlation reasons about, while fitting in a sitting.
const SPEEDS = [
  { value: 10, label: '10x' },
  { value: 20, label: '20x' },
  { value: 60, label: '60x' },
  { value: 0, label: 'All at once' },
];

export function AttackLauncher(props: { onOpenIncident: (id: string) => void }) {
  const catalog = useAsync(() => api.attacks(), []);
  // Polled: a run in progress changes underneath the page.
  const runs = useAsync(() => api.runs(), [], 2000);

  const [speed, setSpeed] = useState(20);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const launch = async (attack: AttackKind) => {
    setBusy(attack.id);
    setFailure(null);
    try {
      const result = await api.launch(attack.id, speed);
      setNotice(result.message);
      runs.reload();
    } catch (error) {
      setFailure(error instanceof Error ? error.message : 'launch failed');
    } finally {
      setBusy(null);
    }
  };

  const clear = async () => {
    setBusy('reset');
    setFailure(null);
    try {
      const result = await api.reset();
      setNotice(result.message);
      runs.reload();
    } catch (error) {
      setFailure(error instanceof Error ? error.message : 'reset failed');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="stack">
      <Panel
        title="Launch an attack"
        aside={
          <div className="inline-controls">
            <span className="faint">tempo</span>
            {SPEEDS.map((option) => (
              <button
                key={option.value}
                type="button"
                className={`chip${speed === option.value ? ' active' : ''}`}
                onClick={() => setSpeed(option.value)}
              >
                {option.label}
              </button>
            ))}
            <button
              type="button"
              className="chip danger"
              disabled={busy !== null}
              onClick={clear}
              title="Clear observed telemetry and start from an empty console"
            >
              CLEAR TELEMETRY
            </button>
          </div>
        }
      >
        {failure ? <ErrorBanner message={failure} /> : null}
        {notice ? <div className="notice">{notice}</div> : null}

        {catalog.error ? <ErrorBanner message={catalog.error} /> : null}
        {catalog.loading && !catalog.data ? <Loading what="playbooks" /> : null}

        {catalog.data ? (
          <>
            <p className="dim narrow">{catalog.data.note}</p>

            <div className="attack-grid">
              {catalog.data.attacks.map((attack) => (
                <article key={attack.id} className="attack-card">
                  <header>
                    <SeverityTag severity={attack.severity_hint} />
                    <span className="attack-category">{attack.category}</span>
                  </header>

                  <h4>{attack.name}</h4>
                  <p className="dim">{attack.description}</p>

                  <dl className="kv compact">
                    <dt>Events</dt>
                    <dd>{attack.event_count}</dd>
                    <dt>Span</dt>
                    <dd>{Math.round(attack.duration_seconds / 60)} min at 1x</dd>
                    <dt>Expected</dt>
                    <dd>{attack.expected_detections.length} detections</dd>
                  </dl>

                  <div className="tactic-tags">
                    {attack.expected_tactics.map((tactic) => (
                      <span key={tactic} className="tag">
                        {tactic}
                      </span>
                    ))}
                  </div>

                  <button
                    type="button"
                    className="primary"
                    disabled={busy !== null}
                    onClick={() => launch(attack)}
                  >
                    {busy === attack.id ? 'LAUNCHING\u2026' : 'LAUNCH'}
                  </button>
                </article>
              ))}
            </div>
          </>
        ) : null}
      </Panel>

      <Panel
        title="Attack history"
        aside={
          runs.data ? (
            <span className="faint">
              {runs.data.running > 0
                ? `${runs.data.running} in progress`
                : `${runs.data.total} launched`}
            </span>
          ) : null
        }
      >
        {runs.data && runs.data.runs.length > 0 ? (
          <table className="data">
            <thead>
              <tr>
                <th>Run</th>
                <th>Attack</th>
                <th>Site</th>
                <th>Progress</th>
                <th>Detections</th>
                <th>Incident</th>
                <th>Launched</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.runs.map((run) => (
                <RunRow key={run.run_id} run={run} onOpenIncident={props.onOpenIncident} />
              ))}
            </tbody>
          </table>
        ) : (
          <p className="dim">
            Nothing launched yet. The console is watching a quiet estate; pick a playbook above and
            the detections, graph and incident will build up as the events arrive.
          </p>
        )}
      </Panel>
    </div>
  );
}

function RunRow(props: { run: AttackRun; onOpenIncident: (id: string) => void }) {
  const { run } = props;
  const running = run.status === 'running';

  return (
    <tr className={running ? 'live' : undefined}>
      <td className="mono">{run.run_id}</td>
      <td>
        {run.name}
        <div className="faint tiny">{run.category}</div>
      </td>
      <td className="mono faint">{run.campus}</td>
      <td>
        <div className="progress" title={`${run.events_delivered} of ${run.events_total} events`}>
          <div
            className={`progress-fill${running ? ' running' : ''}`}
            style={{ width: `${run.progress_percent}%` }}
          />
        </div>
        <div className="faint tiny">
          {run.events_delivered}/{run.events_total} &middot; {run.status_label}
        </div>
      </td>
      <td className="mono">{run.signals_raised.length}</td>
      <td>
        {run.incident_ids.length === 0 ? (
          <span className="faint">
            {running ? 'correlating\u2026' : 'left as signals'}
          </span>
        ) : (
          run.incident_ids.map((id) => (
            <button
              key={id}
              type="button"
              className="link"
              onClick={() => props.onOpenIncident(id)}
            >
              {id}
            </button>
          ))
        )}
      </td>
      <td className="mono faint">{new Date(run.launched_at).toLocaleTimeString()}</td>
    </tr>
  );
}
