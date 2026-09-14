import { useEffect, useState } from 'react';

import { api } from './api';
import { useAsync } from './hooks';
import { IncidentDetail } from './components/IncidentDetail';
import { IncidentTable, Overview } from './components/Overview';
import { Sources } from './components/Sources';
import { Empty, ErrorBanner, Loading, Panel } from './components/common';

type View = 'overview' | 'incidents' | 'sources';

interface Route {
  view: View;
  incidentId: string | null;
}

/// Routing lives in the URL hash so an incident can be linked to, reloaded, and
/// opened directly, rather than only reachable by clicking through the queue.
function parseHash(hash: string): Route {
  const parts = hash.replace(/^#\/?/, '').split('/').filter(Boolean);

  if (parts[0] === 'incidents') {
    return { view: 'incidents', incidentId: parts[1] ?? null };
  }
  if (parts[0] === 'sources') {
    return { view: 'sources', incidentId: null };
  }
  return { view: 'overview', incidentId: null };
}

function toHash(route: Route): string {
  if (route.view === 'incidents') {
    return route.incidentId ? `#/incidents/${route.incidentId}` : '#/incidents';
  }
  return `#/${route.view}`;
}

export function App() {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const go = (next: Route) => {
    window.location.hash = toHash(next);
    setRoute(next);
  };

  const view = route.view;
  const openIncident = route.incidentId;
  const health = useAsync(() => api.health(), [], 15000);

  const open = (id: string) => go({ view: 'incidents', incidentId: id });

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          LIBRAX <small>SOC</small>
        </div>

        <nav className="nav">
          <button
            data-active={view === 'overview'}
            onClick={() => go({ view: 'overview', incidentId: null })}
          >
            Overview
          </button>
          <button
            data-active={view === 'incidents'}
            onClick={() => go({ view: 'incidents', incidentId: null })}
          >
            Incidents
          </button>
          <button
            data-active={view === 'sources'}
            onClick={() => go({ view: 'sources', incidentId: null })}
          >
            Sources
          </button>
        </nav>

        <div className="topbar-right">
          {health.data ? (
            <>
              <span>{health.data.attack_dataset}</span>
              <span>{health.data.detectors} detectors</span>
              {health.data.demo_mode ? <span className="tag sev-medium">demo mode</span> : null}
              <span className="tag sev-low">{health.data.status}</span>
            </>
          ) : (
            <span className="tag sev-critical">api unreachable</span>
          )}
        </div>
      </header>

      <main className="main">
        {view === 'overview' ? <Overview onOpen={open} /> : null}

        {view === 'incidents' ? (
          openIncident ? (
            <IncidentDetail
              id={openIncident}
              onBack={() => go({ view: 'incidents', incidentId: null })}
            />
          ) : (
            <IncidentQueue onOpen={open} />
          )
        ) : null}

        {view === 'sources' ? <Sources /> : null}
      </main>
    </div>
  );
}

function IncidentQueue({ onOpen }: { onOpen: (id: string) => void }) {
  const incidents = useAsync(() => api.incidents(), [], 5000);

  if (incidents.error && !incidents.data) {
    return <ErrorBanner message={incidents.error} />;
  }
  if (!incidents.data) {
    return <Loading what="incidents" />;
  }

  return (
    <Panel
      title={`Incident queue (${incidents.data.total})`}
      flush
      aside={
        <span className="faint mono" style={{ fontSize: 10 }}>
          highest risk first
        </span>
      }
    >
      {incidents.data.incidents.length === 0 ? (
        <Empty what="No incidents have been raised" />
      ) : (
        <IncidentTable incidents={incidents.data.incidents} onOpen={onOpen} />
      )}
    </Panel>
  );
}
