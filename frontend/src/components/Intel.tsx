import { useState } from 'react';

import { api } from '../api';
import { useAsync } from '../hooks';
import type { FileView, IocRecord, IocVerdict, LookupResponse } from '../types';
import { Empty, ErrorBanner, Loading, Panel } from './common';
import { EntityIcon } from './icons';

/// Examples an analyst can click instead of typing 64 hex characters.
const SAMPLES = [
  { label: 'Phishing attachment (MD5)', value: '3d8f1a52c7b04e69a1d3f8025b6c9e74' },
  { label: 'Ransomware binary (SHA256)', value: 'e78b3c19d05af64721c8e93b0d6f47a5c21e98b34f07d5a6e1b92c48037fa5d1' },
  { label: 'PowerShell (SHA256)', value: '6b1f80c3a94e27d5b0c8f61a3e07d924b5c8a01f7e63d24a9b05c8f31e7a06d2' },
  { label: 'Attacker address', value: '185.220.101.47' },
  { label: 'Travelling-user VPN exit', value: '203.0.113.77' },
  { label: 'C2 domain', value: 'cdn-sync-update.net' },
];

function VerdictBadge({ verdict, label }: { verdict: IocVerdict; label: string }) {
  return <span className={`verdict ${verdict}`}>{label}</span>;
}

export function IntelView(props: { onOpenIncident: (id: string) => void }) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<LookupResponse | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const lookup = async (value: string) => {
    const needle = value.trim();
    if (!needle) return;

    setBusy(true);
    setFailure(null);
    try {
      setResult(await api.lookup(needle));
    } catch (error) {
      setResult(null);
      setFailure(error instanceof Error ? error.message : 'lookup failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <Panel title="Indicator lookup">
        <form
          className="search-bar"
          onSubmit={(event) => {
            event.preventDefault();
            void lookup(input);
          }}
        >
          <input
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="MD5, SHA256, IPv4 or domain"
            spellCheck={false}
            autoComplete="off"
          />
          <button type="submit" className="primary" disabled={busy}>
            {busy ? 'CHECKING\u2026' : 'CHECK'}
          </button>
        </form>

        <div className="sample-row">
          <span className="faint tiny">try</span>
          {SAMPLES.map((sample) => (
            <button
              key={sample.value}
              type="button"
              className="chip"
              onClick={() => {
                setInput(sample.value);
                void lookup(sample.value);
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>

        {failure ? <ErrorBanner message={failure} /> : null}
        {result ? <LookupResult result={result} onOpenIncident={props.onOpenIncident} /> : null}
      </Panel>

      <FilesPanel />
      <FeedPanel onLookup={(value) => { setInput(value); void lookup(value); }} />
    </div>
  );
}

function LookupResult(props: {
  result: LookupResponse;
  onOpenIncident: (id: string) => void;
}) {
  const { result } = props;
  const { record } = result;

  return (
    <div className="lookup-result">
      <div className="lookup-head">
        <VerdictBadge verdict={record.verdict} label={record.verdict_label} />
        <code className="lookup-value">{result.query}</code>
        <span className="faint">{result.kind_label}</span>
        {result.observed_here ? (
          <span className="tag sev-high">SEEN IN THIS ESTATE</span>
        ) : (
          <span className="tag">not observed here</span>
        )}
      </div>

      <p className="assessment">{result.assessment}</p>

      <div className="two-col">
        <dl className="kv">
          {record.threat_name ? (
            <>
              <dt>Threat</dt>
              <dd>{record.threat_name}</dd>
            </>
          ) : null}
          {record.malware_family ? (
            <>
              <dt>Family</dt>
              <dd>{record.malware_family}</dd>
            </>
          ) : null}
          {record.detection_ratio ? (
            <>
              <dt>Engines</dt>
              <dd className="mono">{record.detection_ratio}</dd>
            </>
          ) : null}
          {record.signed !== null ? (
            <>
              <dt>Signed</dt>
              <dd>{record.signed ? (record.signer ?? 'yes') : 'no'}</dd>
            </>
          ) : null}
          {record.file_names.length > 0 ? (
            <>
              <dt>Filenames</dt>
              <dd className="mono">{record.file_names.join(', ')}</dd>
            </>
          ) : null}
          {record.asn ? (
            <>
              <dt>Network</dt>
              <dd>{record.asn}</dd>
            </>
          ) : null}
          {record.country ? (
            <>
              <dt>Country</dt>
              <dd>{record.country}</dd>
            </>
          ) : null}
          {record.hosting ? (
            <>
              <dt>Hosting</dt>
              <dd>{record.hosting}</dd>
            </>
          ) : null}
          <dt>Feeds</dt>
          <dd>{record.feeds.length > 0 ? record.feeds.join(', ') : 'none'}</dd>
          {record.first_reported ? (
            <>
              <dt>First reported</dt>
              <dd>{new Date(record.first_reported).toLocaleDateString()}</dd>
            </>
          ) : null}
        </dl>

        <div>
          {record.categories.length > 0 ? (
            <div className="tactic-tags">
              {record.categories.map((category) => (
                <span key={category} className="tag">
                  {category}
                </span>
              ))}
            </div>
          ) : null}

          {record.notes.map((note, i) => (
            <p key={i} className="dim note">
              {note}
            </p>
          ))}

          {result.incident_ids.length > 0 ? (
            <p>
              Contributing to{' '}
              {result.incident_ids.map((id) => (
                <button
                  key={id}
                  type="button"
                  className="link"
                  onClick={() => props.onOpenIncident(id)}
                >
                  {id}
                </button>
              ))}
            </p>
          ) : null}
        </div>
      </div>

      {result.sightings.length > 0 ? (
        <div>
          <div className="label faint">
            SIGHTINGS IN RETAINED TELEMETRY ({result.sighting_count})
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>Event</th>
                <th>Time</th>
                <th>Source</th>
                <th>Host</th>
                <th>User</th>
                <th>Matched on</th>
              </tr>
            </thead>
            <tbody>
              {result.sightings.map((sighting) => (
                <tr key={sighting.event_id}>
                  <td className="mono">{sighting.event_id}</td>
                  <td className="mono faint">
                    {new Date(sighting.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="mono faint">{sighting.source_id}</td>
                  <td className="mono">{sighting.host ?? '\u2014'}</td>
                  <td className="mono">{sighting.user ?? '\u2014'}</td>
                  <td className="faint">{sighting.matched_field}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

/// Files observed on the fleet, filtered the way a triage analyst filters them:
/// worst verdict first, and "show me only what is not clean".
function FilesPanel() {
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [badOnly, setBadOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const files = useAsync(
    () => api.files({ name, host, bad_only: badOnly, limit: 60 }),
    [name, host, badOnly],
    6000,
  );

  return (
    <Panel
      title="Observed files"
      aside={
        files.data ? (
          <span className="faint">
            {files.data.total} distinct &middot; {files.data.malicious} malicious &middot;{' '}
            {files.data.unknown} unassessed
          </span>
        ) : null
      }
    >
      <div className="filter-bar">
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="filter by filename"
          spellCheck={false}
        />
        <input
          value={host}
          onChange={(event) => setHost(event.target.value)}
          placeholder="filter by host"
          spellCheck={false}
        />
        <button
          type="button"
          className={`chip${badOnly ? ' active' : ''}`}
          onClick={() => setBadOnly(!badOnly)}
        >
          NOT CLEAN ONLY
        </button>
      </div>

      {files.error ? <ErrorBanner message={files.error} /> : null}
      {files.loading && !files.data ? <Loading what="observed files" /> : null}

      {files.data && files.data.files.length === 0 ? (
        <Empty what="No files match these filters" />
      ) : null}

      {files.data && files.data.files.length > 0 ? (
        <table className="data">
          <thead>
            <tr>
              <th>File</th>
              <th>Verdict</th>
              <th>Engines</th>
              <th>Signed</th>
              <th>Hosts</th>
              <th>Executions</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {files.data.files.map((file) => (
              <FileRow
                key={file.sha256 ?? file.md5 ?? file.name}
                file={file}
                expanded={expanded === (file.sha256 ?? file.name)}
                onToggle={() =>
                  setExpanded(
                    expanded === (file.sha256 ?? file.name) ? null : (file.sha256 ?? file.name),
                  )
                }
              />
            ))}
          </tbody>
        </table>
      ) : null}
    </Panel>
  );
}

function FileRow(props: { file: FileView; expanded: boolean; onToggle: () => void }) {
  const { file } = props;

  return (
    <>
      <tr className="clickable" onClick={props.onToggle}>
        <td>
          <EntityIcon kind="file" /> <span className="mono">{file.name}</span>
        </td>
        <td>
          <VerdictBadge verdict={file.verdict} label={file.verdict_label} />
        </td>
        <td className="mono faint">{file.detection_ratio ?? '\u2014'}</td>
        <td className="faint">
          {file.signed === null ? '\u2014' : file.signed ? (file.signer ?? 'yes') : 'no'}
        </td>
        <td className="mono">{file.host_count}</td>
        <td className="mono">{file.execution_count}</td>
        <td className="mono faint">{new Date(file.last_seen).toLocaleTimeString()}</td>
      </tr>

      {props.expanded ? (
        <tr className="detail-row">
          <td colSpan={7}>
            <dl className="kv">
              <dt>SHA256</dt>
              <dd className="mono breakable">{file.sha256 ?? 'not reported by the source'}</dd>
              <dt>MD5</dt>
              <dd className="mono breakable">{file.md5 ?? 'not reported by the source'}</dd>
              {file.threat_name ? (
                <>
                  <dt>Threat</dt>
                  <dd>
                    {file.threat_name}
                    {file.malware_family ? ` \u00b7 ${file.malware_family}` : ''}
                  </dd>
                </>
              ) : null}
              <dt>Hosts</dt>
              <dd className="mono">
                {file.hosts.join(', ')}
                {file.host_count > file.hosts.length
                  ? ` +${file.host_count - file.hosts.length} more`
                  : ''}
              </dd>
              {file.command_lines.length > 0 ? (
                <>
                  <dt>Command lines</dt>
                  <dd className="mono breakable">
                    {file.command_lines.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))}
                  </dd>
                </>
              ) : null}
            </dl>

            {file.notes.map((note, i) => (
              <p key={i} className="dim note">
                {note}
              </p>
            ))}
          </td>
        </tr>
      ) : null}
    </>
  );
}

/// The whole feed, so the analyst can see the limits of what the system knows.
function FeedPanel(props: { onLookup: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const feed = useAsync(() => (open ? api.indicators() : Promise.resolve(null)), [open]);

  return (
    <Panel
      title="Indicator feed"
      aside={
        <button type="button" className="chip" onClick={() => setOpen(!open)}>
          {open ? 'HIDE' : 'SHOW'}
        </button>
      }
    >
      {!open ? (
        <p className="dim">
          The local feed backing every verdict on this page. Worth reading before trusting one: a
          verdict is only ever as good as the feed behind it.
        </p>
      ) : null}

      {open && feed.loading && !feed.data ? <Loading what="the feed" /> : null}

      {open && feed.data ? (
        <>
          <p className="dim narrow">{feed.data.note}</p>
          <table className="data">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Type</th>
                <th>Indicator</th>
                <th>Threat</th>
                <th>Categories</th>
              </tr>
            </thead>
            <tbody>
              {feed.data.indicators.map((record: IocRecord) => (
                <tr
                  key={`${record.kind}-${record.value}`}
                  className="clickable"
                  onClick={() => props.onLookup(record.value)}
                >
                  <td>
                    <VerdictBadge verdict={record.verdict} label={record.verdict_label} />
                  </td>
                  <td className="faint">{record.kind_label}</td>
                  <td className="mono breakable">{record.value}</td>
                  <td>{record.threat_name ?? (record.file_names[0] ?? '\u2014')}</td>
                  <td className="faint tiny">{record.categories.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </Panel>
  );
}
