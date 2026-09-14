import { useCallback, useEffect, useState } from 'react';

import { ApiError } from './api';

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/// Loads data on mount and whenever `deps` change, optionally polling.
///
/// Polling never clears already-rendered data on a transient failure: a SOC
/// console that blanks out because one refresh timed out is worse than one
/// showing data a few seconds stale.
export function useAsync<T>(
  load: () => Promise<T>,
  deps: unknown[] = [],
  pollMs?: number,
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;

    const run = async (isRefresh: boolean) => {
      if (!isRefresh) {
        setLoading(true);
      }
      try {
        const result = await load();
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          const message = e instanceof ApiError ? e.message : String(e);
          setError(message);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void run(false);

    if (!pollMs) {
      return () => {
        cancelled = true;
      };
    }

    const timer = setInterval(() => void run(true), pollMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, pollMs]);

  return { data, error, loading, reload };
}
