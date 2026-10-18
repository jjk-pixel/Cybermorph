import { useCallback, useEffect, useRef, useState } from "react";

export type Resource<T> = {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
};

/* Charge une ressource REST, avec rafraîchissement périodique optionnel. Conserve la dernière donnée valide en cas d'erreur. */
export function useResource<T>(loader: () => Promise<T>, deps: unknown[], refreshMs?: number): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const generation = useRef(0);

  const run = useCallback(() => {
    const current = ++generation.current;
    setLoading(true);
    loaderRef.current()
      .then((value) => {
        if (current !== generation.current) return;
        setData(value);
        setError(null);
      })
      .catch((e: Error) => {
        if (current === generation.current) setError(e.message);
      })
      .finally(() => {
        if (current === generation.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
    if (!refreshMs) return;
    const timer = window.setInterval(run, refreshMs);
    return () => window.clearInterval(timer);
  }, [run, refreshMs]);

  return { data, error, loading, reload: run };
}
