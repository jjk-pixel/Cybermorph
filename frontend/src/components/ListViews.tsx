import { useEffect, useState } from "react";

const API = "http://192.168.43.135:8000";

function useFetch<T>(url: string) {
  const [data, setData] = useState<T | null>(null);
  useEffect(() => {
    fetch(url).then((r) => r.json()).then(setData);
  }, [url]);
  return data;
}

export function AlertsView() {
  const alerts = useFetch<any[]>(`${API}/api/alerts/`);
  return (
    <div className="list-view">
      <h1>Alertes Suricata</h1>
      {alerts?.map((a) => (
        <div className="data-row" key={a.id}>
          <div className="msg">{a.message}</div>
          <div className="meta">×{a.occurrence_count} · priorité {a.priority} · {a.source_ip} → {a.destination_ip}</div>
        </div>
      ))}
      {alerts?.length === 0 && <p style={{ color: "#7C8798" }}>Aucune alerte pour le moment.</p>}
    </div>
  );
}

export function PathsView() {
  const data = useFetch<{ paths: any[] }>(`${API}/api/attack-paths/`);
  return (
    <div className="list-view">
      <h1>Chemins d'attaque</h1>
      {data?.paths.map((p, i) => (
        <div className="data-row" key={i}>
          <div className="msg">{p.source_ip} → {p.target_ip} ({p.hops} saut{p.hops > 1 ? "s" : ""})</div>
          <div className="meta">score {p.score} · {p.risk} · preuve : {p.evidence_level}</div>
        </div>
      ))}
    </div>
  );
}

export function MitreView() {
  const techniques = useFetch<any[]>(`${API}/api/attack-techniques/observed`);
  return (
    <div className="list-view">
      <h1>Techniques MITRE ATT&CK observées</h1>
      {techniques?.map((t) => (
        <div key={t.technique_id} style={{ marginBottom: 24 }}>
          <div className="msg" style={{ fontSize: 14, fontWeight: 600 }}>
            {t.technique_id} — {t.name} <span style={{ color: "#7C8798", fontWeight: 400 }}>({t.tactic})</span>
          </div>
          {t.alerts.map((a: any, i: number) => (
            <div className="data-row" key={i} style={{ paddingLeft: 12 }}>
              <div className="msg" style={{ fontSize: 12 }}>{a.message}</div>
              <div className="meta">×{a.occurrence_count} · confiance {a.confidence}</div>
            </div>
          ))}
        </div>
      ))}
      {techniques?.length === 0 && <p style={{ color: "#7C8798" }}>Aucune technique détectée pour le moment.</p>}
    </div>
  );
}

export function TimelineView() {
  const snapshots = useFetch<any[]>(`${API}/api/timeline/`);

  // Les snapshots arrivent du plus récent au plus ancien (ordre API).
  // On regroupe les runs consécutifs identiques (même compteurs) en une seule ligne.
  const grouped: { first: any; last: any; count: number }[] = [];
  if (snapshots) {
    const sorted = [...snapshots].sort(
      (a, b) => new Date(b.captured_at).getTime() - new Date(a.captured_at).getTime()
    );
    for (const s of sorted) {
      const key = `${s.assets_count}-${JSON.stringify(s.connections_count)}-${s.attack_paths_count}-${s.highest_path_score}`;
      const lastGroup = grouped[grouped.length - 1];
      const lastKey = lastGroup
        ? `${lastGroup.last.assets_count}-${JSON.stringify(lastGroup.last.connections_count)}-${lastGroup.last.attack_paths_count}-${lastGroup.last.highest_path_score}`
        : null;

      if (lastGroup && key === lastKey) {
        lastGroup.count += 1;
        lastGroup.last = s; // le plus ancien de ce groupe, puisqu'on descend dans le temps
      } else {
        grouped.push({ first: s, last: s, count: 1 });
      }
    }
  }

  return (
    <div className="list-view">
      <h1>Timeline / Replay</h1>
      {grouped.map((g, i) => (
        <div className="data-row" key={i}>
          <div className="msg">
            {new Date(g.last.captured_at).toLocaleString("fr-FR")}
            {g.count > 1 && (
              <span style={{ color: "#7C8798" }}>
                {" "}→ {new Date(g.first.captured_at).toLocaleString("fr-FR")} ({g.count} cycles sans changement)
              </span>
            )}
          </div>
          <div className="meta">
            {g.first.assets_count} actifs · {g.first.attack_paths_count} chemins · score max {g.first.highest_path_score}
          </div>
        </div>
      ))}
      {grouped.length === 0 && <p style={{ color: "#7C8798" }}>Aucun historique pour le moment.</p>}
    </div>
  );
}
