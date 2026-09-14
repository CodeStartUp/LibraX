import { useState } from 'react';

import { api } from '../api';
import { useAsync } from '../hooks';
import type { EventRow } from '../types';
import { Empty, ErrorBanner, Loading, Panel, SeverityTag, num } from './common';

const SOURCES = [
  'active_directory',
  'edr',
  'firewall',
  'vpn',
  'pam',
  'dns',
  'server',
  'database',
  'pacs',
  'email',
  'cloud',
];

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

/// Raw telemetry search.
///
/// Deliberately secondary to the incident view: an analyst should not need this
/// to understand what happened. It exists for the moment they distrust the
/// correlated story and want to read the logs themselves.
export function EventSearch() {
  const [q, setQ] = useState('');
  const [sourceType, setSourceType] = useState('');
  const [severity, setSeverity] = useState('');
  const [host, setHost] = useState('');
  const [user, setUser] = useState('');
  const [evidenceOnly, setEvidenceOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const events = useAsync(
    () =>
      api.events({
        q,
        source_type: sourceType,
        min_severity: severity,
        host,
        user,
        evidence_only: evidenceOnly,
        limit: 120,
      }),
    [q, sourceType, severity, host, user, evidenceOnly],
    5000,
  );

  const clear = () => {
    setQ('');
    setSourceType('');
    setSeverity('');
    setHost('');
    setUser('');
    setEvidenceOnly(false);
  };

  const active = q || sourceType || severity || host || user || evidenceOnly;

  return (
    <Panel
      title="Telemetry search"
      aside={
        events.data ? (
          <span className="faint">
            {num(events.data.matched)} of {num(events.data.total_retained)} retained events
          </span>
        ) : null
      }
    >
      <div className="filter-bar">
        <input
          className="grow"
          value={q}
          onChange={(event) => setQ(event.target.value)}
          placeholder={'search message, host, user, address, hash, command line\u2026'}
          spellCheck={false}
        />
        <select value={sourceType} onChange={(event) => setSourceType(event.target.value)}>
          <option value="">any source</option>
          {SOURCES.map((source) => (
            <option key={source} value={source}>
              {source.replace('_', ' ')}
            </option>
          ))}
        </select>
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">any severity</option>
          {SEVERITIES.map((level) => (
            <option key={level} value={level}>
              {level} and above
            </option>
          ))}
        </select>
      </div>

      <div className="filter-bar">
        <input
          value={host}
          onChange={(event) => setHost(event.target.value)}
          placeholder="host"
          spellCheck={false}
        />
        <input
          value={user}
          onChange={(event) => setUser(event.target.value)}
          placeholder="user or account"
          spellCheck={false}
        />
        <button
          type="button"
          className={`chip${evidenceOnly ? ' active' : ''}`}
          onClick={() => setEvidenceOnly(!evidenceOnly)}
          title="Only events that a detector cited as evidence"
        >
          EVIDENCE ONLY
        </button>
        {active ? (
          <button type="button" className="chip" onClick={clear}>
            CLEAR
          </button>
        ) : null}
      </div>

      {events.error ? <ErrorBanner message={events.error} /> : null}
      {events.loading && !events.data ? <Loading what="telemetry" /> : null}

      {events.data && events.data.events.length === 0 ? (
        <Empty what="No events match these filters" />
      ) : null}

      {events.data && events.data.events.length > 0 ? (
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Activity</th>
              <th>Host</th>
              <th>User</th>
              <th>Severity</th>
              <th>Detections</th>
            </tr>
          </thead>
          <tbody>
            {events.data.events.map((event) => (
              <Row
                key={event.event_id}
                event={event}
                expanded={expanded === event.event_id}
                onToggle={() =>
                  setExpanded(expanded === event.event_id ? null : event.event_id)
                }
              />
            ))}
          </tbody>
        </table>
      ) : null}

      {events.data && events.data.matched > events.data.returned ? (
        <p className="faint tiny">
          Showing the {events.data.returned} most recent of {num(events.data.matched)} matches.
          Narrow the filters to see the rest.
        </p>
      ) : null}
    </Panel>
  );
}

function Row(props: { event: EventRow; expanded: boolean; onToggle: () => void }) {
  const { event } = props;

  return (
    <>
      <tr
        className={`clickable${event.signal_ids.length > 0 ? ' flagged' : ''}`}
        onClick={props.onToggle}
      >
        <td className="mono faint">{new Date(event.timestamp).toLocaleTimeString()}</td>
        <td className="mono faint">{event.source_id}</td>
        <td>{event.activity}</td>
        <td className="mono">{event.host ?? '\u2014'}</td>
        <td className="mono">{event.user ?? '\u2014'}</td>
        <td>
          <SeverityTag severity={event.severity} />
        </td>
        <td className="mono">{event.signal_ids.length > 0 ? event.signal_ids.length : ''}</td>
      </tr>

      {props.expanded ? (
        <tr className="detail-row">
          <td colSpan={7}>
            <p>{event.message}</p>
            <dl className="kv">
              <dt>Event id</dt>
              <dd className="mono">{event.event_id}</dd>
              <dt>Category</dt>
              <dd>{event.category}</dd>
              {event.process ? (
                <>
                  <dt>Process</dt>
                  <dd className="mono">{event.process}</dd>
                </>
              ) : null}
              {event.command_line ? (
                <>
                  <dt>Command line</dt>
                  <dd className="mono breakable">{event.command_line}</dd>
                </>
              ) : null}
              {event.sha256 ? (
                <>
                  <dt>SHA256</dt>
                  <dd className="mono breakable">{event.sha256}</dd>
                </>
              ) : null}
              {event.md5 ? (
                <>
                  <dt>MD5</dt>
                  <dd className="mono breakable">{event.md5}</dd>
                </>
              ) : null}
              {event.src_ip || event.dst_ip ? (
                <>
                  <dt>Addresses</dt>
                  <dd className="mono">
                    {event.src_ip ?? '\u2014'} &rarr; {event.dst_ip ?? '\u2014'}
                  </dd>
                </>
              ) : null}
              {event.hospital ? (
                <>
                  <dt>Site</dt>
                  <dd>{event.hospital}</dd>
                </>
              ) : null}
              {event.signal_ids.length > 0 ? (
                <>
                  <dt>Evidence for</dt>
                  <dd className="mono">{event.signal_ids.join(', ')}</dd>
                </>
              ) : null}
            </dl>
          </td>
        </tr>
      ) : null}
    </>
  );
}
