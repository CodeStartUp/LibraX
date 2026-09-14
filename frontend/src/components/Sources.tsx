import { api } from '../api';
import { useAsync } from '../hooks';
import { Empty, ErrorBanner, Loading, Panel, num } from './common';

const STATUS_TONE: Record<string, string> = {
  healthy: 'sev-low',
  warning: 'sev-medium',
  blind_spot: 'sev-critical',
  offline: 'sev-info',
};

export function Sources() {
  const sources = useAsync(() => api.sources(), [], 5000);

  if (sources.error && !sources.data) {
    return <ErrorBanner message={sources.error} />;
  }
  if (!sources.data) {
    return <Loading what="source health" />;
  }

  const byStatus = (status: string) =>
    sources.data!.sources.filter((s) => s.status === status).length;

  return (
    <div>
      {sources.data.all_synthetic ? (
        <div className="banner warn">
          Every source below is simulator-backed. These are not live integrations with real
          hospital systems, and the console labels them as such rather than implying otherwise.
        </div>
      ) : null}

      <Panel
        title="Data source health"
        flush
        aside={
          <span className="faint mono" style={{ fontSize: 10 }}>
            {sources.data.total} connectors · {byStatus('healthy')} healthy ·{' '}
            {byStatus('warning')} warning · {byStatus('blind_spot') + byStatus('offline')} blind
          </span>
        }
      >
        {sources.data.sources.length === 0 ? (
          <Empty what="No connector has reported yet" />
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Source</th>
                <th>Type</th>
                <th>Status</th>
                <th className="right">Events/min</th>
                <th className="right">Observed</th>
                <th>Coverage</th>
                <th className="right">Errors</th>
                <th>Last event</th>
              </tr>
            </thead>
            <tbody>
              {sources.data.sources.map((source) => (
                <tr key={source.source_id}>
                  <td className="mono">{source.source_id}</td>
                  <td className="dim">{source.label}</td>
                  <td>
                    <span className={`tag ${STATUS_TONE[source.status] ?? 'sev-info'}`}>
                      {source.status_label}
                    </span>
                  </td>
                  <td className="right mono">{num(source.events_per_minute, 1)}</td>
                  <td className="right mono dim">{num(source.events_observed)}</td>
                  <td>
                    {source.assets_expected > 0 ? (
                      <div>
                        <span className="mono" style={{ fontSize: 11 }}>
                          {num(source.assets_reporting)} / {num(source.assets_expected)} (
                          {source.coverage_percent.toFixed(1)}%)
                        </span>
                        <div className="bar" style={{ marginTop: 2, width: 120 }}>
                          <span
                            style={{
                              width: `${source.coverage_percent}%`,
                              background:
                                source.coverage_percent < 95 ? 'var(--medium)' : 'var(--low)',
                            }}
                          />
                        </div>
                      </div>
                    ) : (
                      <span className="faint">—</span>
                    )}
                  </td>
                  <td className="right mono">{source.error_count || '—'}</td>
                  <td className="mono faint">
                    {source.last_event_at
                      ? new Date(source.last_event_at).toLocaleTimeString()
                      : 'never'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
