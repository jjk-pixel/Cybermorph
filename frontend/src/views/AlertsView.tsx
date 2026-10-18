import { useMemo, useState } from "react";
import { api } from "../api/client";
import { EmptyState, ErrorNote, Panel, PriorityTag } from "../components/ui";
import { formatCount, formatDateTime, priorityBand } from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { ui } from "../state/ui";

const PRIORITY_FILTERS = [
  { value: 0, label: "Toutes" },
  { value: 1, label: "P1" },
  { value: 2, label: "P1–P2" },
  { value: 3, label: "P1–P3" },
];

export function AlertsView() {
  const alerts = useResource(() => api.alerts(500), [], 15_000);
  const techniques = useResource(() => api.observedTechniques(), [], 60_000);
  const { byIp } = useAssetIndex();
  const [maxPriority, setMaxPriority] = useState(0);
  const [search, setSearch] = useState("");

  const techniqueByAlert = useMemo(() => {
    const map = new Map<number, string>();
    for (const t of techniques.data ?? []) for (const a of t.alerts) map.set(a.alert_id, t.technique_id);
    return map;
  }, [techniques.data]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (alerts.data ?? []).filter((a) => {
      if (maxPriority && (a.priority ?? 9) > maxPriority) return false;
      if (!q) return true;
      return [a.message, a.classification, a.source_ip, a.destination_ip, techniqueByAlert.get(a.id)]
        .some((v) => v?.toLowerCase().includes(q));
    });
  }, [alerts.data, maxPriority, search, techniqueByAlert]);

  const focusPair = (sourceIp: string, destinationIp: string) => {
    const src = byIp.get(sourceIp);
    const dst = byIp.get(destinationIp);
    if (src) ui.selectAsset(src.id);
    if (src && dst) ui.focusPath({ source: src.id, target: dst.id, nodes: [src.id, dst.id], hops: 1, score: 0, risk: "low", evidence_level: "alerte_ids", connection_types: ["alert"] });
  };

  return (
    <div className="layout-wide">
      <Panel
        className="panel-fill"
        title="Alertes Suricata"
        meta={alerts.data ? `${rows.length} affichée${rows.length > 1 ? "s" : ""} sur ${alerts.data.length} plus récentes` : "Chargement…"}
        actions={
          <div className="filters">
            <div className="segmented" role="group" aria-label="Filtrer par priorité">
              {PRIORITY_FILTERS.map((f) => (
                <button key={f.value} type="button" className={maxPriority === f.value ? "is-on" : ""} aria-pressed={maxPriority === f.value} onClick={() => setMaxPriority(f.value)}>
                  {f.label}
                </button>
              ))}
            </div>
            <input
              type="search"
              className="input"
              placeholder="Signature, IP, technique…"
              aria-label="Rechercher dans les alertes"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        }
      >
        {alerts.error && <ErrorNote message={alerts.error} onRetry={alerts.reload} />}
        {alerts.data && rows.length === 0 && <EmptyState title="Aucune alerte ne correspond">Élargissez le filtre de priorité ou videz la recherche.</EmptyState>}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Priorité</th>
                  <th scope="col">Signature</th>
                  <th scope="col">Flux</th>
                  <th scope="col">Technique</th>
                  <th scope="col" className="num">Occurrences</th>
                  <th scope="col">Dernière vue</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} className={`band-${priorityBand(a.priority)}`}>
                    <td><PriorityTag priority={a.priority} /></td>
                    <td>
                      <div className="cell-main">{a.message}</div>
                      <div className="cell-sub">{a.classification}{a.protocol ? ` · ${a.protocol}` : ""}</div>
                    </td>
                    <td>
                      <button type="button" className="link-button mono" onClick={() => focusPair(a.source_ip, a.destination_ip)} title="Montrer ce flux dans la scène">
                        {a.source_ip} → {a.destination_ip}
                      </button>
                    </td>
                    <td className="mono">{techniqueByAlert.get(a.id) ?? "—"}</td>
                    <td className="mono num">{formatCount(a.occurrence_count)}</td>
                    <td className="nowrap">{formatDateTime(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
