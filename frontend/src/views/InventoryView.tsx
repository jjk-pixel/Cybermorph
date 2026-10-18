import { useMemo, useState } from "react";
import { api } from "../api/client";
import type { AssetChange, InventoryEntry } from "../api/types";
import { AuthorizationTag, ChangeRow } from "../components/inventory";
import { EmptyState, ErrorNote, Meter, Panel } from "../components/ui";
import { ASSET_TYPE_LABEL, formatConfidence, formatDateTime, formatRelative } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";

type Filter = "all" | "unauthorized" | "conflicts" | "new";
const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Tous" },
  { id: "unauthorized", label: "Non autorisés" },
  { id: "conflicts", label: "Conflits" },
  { id: "new", label: "Nouveaux 24 h" },
];

const DAY = 24 * 3600 * 1000;

function matches(entry: InventoryEntry, filter: Filter): boolean {
  if (filter === "unauthorized") return entry.authorization === "unauthorized";
  if (filter === "conflicts") return entry.identity.open_conflicts > 0;
  if (filter === "new") return !!entry.first_seen && Date.now() - new Date(entry.first_seen).getTime() < DAY;
  return true;
}

/* Inventaire rapproché : qui est sur le réseau, à quel point on en est sûr, et ce qui a changé. */
export function InventoryView() {
  const lastScan = useLive((s) => s.state?.last_scan_at);
  const declarations = useLive((s) => (s.state?.assets ?? []).map((a) => `${a.id}:${a.authorization}:${a.is_scanner}`).join(","));
  const inventory = useResource(() => api.inventory(), [lastScan, declarations]);
  const selectedId = useUi((s) => s.selectedAssetId);
  const [filter, setFilter] = useState<Filter>("all");
  const [minSeverity, setMinSeverity] = useState("notice");
  const [hideAcknowledged, setHideAcknowledged] = useState(false);
  const [ackError, setAckError] = useState<string | null>(null);

  const changes = useResource(
    () => api.changes({ limit: 200, asset_id: selectedId ?? undefined, min_severity: minSeverity, include_acknowledged: !hideAcknowledged }),
    [selectedId, minSeverity, hideAcknowledged, lastScan],
  );

  const entries = useMemo(() => (inventory.data?.assets ?? []).filter((e) => matches(e, filter)), [inventory.data, filter]);
  const byId = useMemo(() => new Map((inventory.data?.assets ?? []).map((e) => [e.id, e])), [inventory.data]);
  const label = (id: number) => byId.get(id)?.ip ?? `#${id}`;

  const acknowledge = async (change: AssetChange) => {
    setAckError(null);
    try {
      await api.acknowledgeChange(change.id);
      changes.reload();
      inventory.reload();
    } catch (e) {
      setAckError((e as Error).message);
    }
  };

  const data = inventory.data;
  const learning = data?.learning;

  return (
    <div className="layout-split layout-inventory">
      <Panel
        className="panel-fill inventory-panel"
        title="Inventaire"
        meta={data ? `${data.stats.assets} actifs · ${data.stats.unauthorized} non autorisé${data.stats.unauthorized > 1 ? "s" : ""} · ${data.stats.conflicts} conflit${data.stats.conflicts > 1 ? "s" : ""} d'identité` : "Chargement…"}
      >
        {learning && (
          <p className={`learning-note${learning.in_learning ? " is-learning" : ""}`}>
            {learning.in_learning
              ? <>Apprentissage en cours jusqu'au <strong>{formatDateTime(learning.ends_at)}</strong> : un actif découvert d'ici là est autorisé d'office.</>
              : <>Apprentissage terminé le {formatDateTime(learning.ends_at)} : tout nouvel actif est marqué non autorisé jusqu'à validation.</>}
          </p>
        )}
        <div className="filters">
          <div className="segmented" role="group" aria-label="Filtrer l'inventaire">
            {FILTERS.map((f) => (
              <button key={f.id} type="button" className={filter === f.id ? "is-on" : ""} aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {f.label}
              </button>
            ))}
          </div>
        </div>
        {inventory.error && <ErrorNote message={inventory.error} onRetry={inventory.reload} />}
        {data && entries.length === 0 && <EmptyState title="Aucun actif pour ce filtre" />}
        {entries.length > 0 && (
          <div className="table-wrap">
            <table className="table inventory-table">
              <thead>
                <tr>
                  <th>Actif</th>
                  <th>Type</th>
                  <th>Identité</th>
                  <th>Statut</th>
                  <th>Vu</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => {
                  const name = e.identity.name;
                  return (
                    <tr key={e.id} className={selectedId === e.id ? "is-selected" : ""} onClick={() => ui.selectAsset(selectedId === e.id ? null : e.id)}>
                      <td>
                        <button type="button" className="link-button mono cell-main" onClick={(ev) => { ev.stopPropagation(); ui.selectAsset(e.id); }}>{e.ip}</button>
                        <span className="cell-sub">
                          {name ? name.value : "sans nom"}
                          {name && !name.observed && <span className="muted"> · déduit</span>}
                          {e.is_scanner && <span className="scanner-flag" title={e.scanner_reason ?? ""}> · scanner</span>}
                        </span>
                      </td>
                      <td>{ASSET_TYPE_LABEL[e.asset_type] ?? e.asset_type}</td>
                      <td className="identity-cell" title={e.identity.reasons.join("\n")}>
                        <Meter value={e.identity.confidence * 100} band={e.identity.open_conflicts ? "high" : "low"} label="Confiance d'identité" />
                        <span className="mono small">{formatConfidence(e.identity.confidence)}</span>
                        {e.identity.open_conflicts > 0 && <span className="tag tag-high">conflit</span>}
                      </td>
                      <td>
                        <AuthorizationTag value={e.authorization} />
                        <span className={`cell-sub ${e.status === "up" ? "is-up" : "is-down"}`}>{e.status === "up" ? "en ligne" : "hors ligne"}</span>
                      </td>
                      <td className="nowrap">
                        <span className="cell-main">{formatRelative(e.last_seen)}</span>
                        <span className="cell-sub">depuis {formatDateTime(e.first_seen)}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">
          L'IP reste la clé d'un actif. Une MAC différente sur la même IP, ou une même MAC sur plusieurs IP, est signalée sans fusion automatique.
        </p>
      </Panel>

      <Panel
        className="panel-fill"
        title={selectedId != null ? `Changements de ${label(selectedId)}` : "Journal des changements"}
        meta={data ? `${data.stats.changes_24h} sur 24 h, tous niveaux` : undefined}
      >
        <div className="filters">
          <div className="segmented" role="group" aria-label="Niveau minimal">
            {[["info", "Tout"], ["notice", "À noter"], ["warning", "À vérifier"]].map(([value, text]) => (
              <button key={value} type="button" className={minSeverity === value ? "is-on" : ""} aria-pressed={minSeverity === value} onClick={() => setMinSeverity(value)}>
                {text}
              </button>
            ))}
          </div>
          <label className="checkbox">
            <input type="checkbox" checked={hideAcknowledged} onChange={(e) => setHideAcknowledged(e.target.checked)} />
            Masquer les acquittés
          </label>
        </div>
        {ackError && <ErrorNote message={ackError} />}
        {changes.error && <ErrorNote message={changes.error} onRetry={changes.reload} />}
        {changes.data && changes.data.length === 0 && (
          <EmptyState title="Aucun changement à ce niveau">
            Les changements apparaissent à partir du deuxième cycle d'inventaire : le premier passage enregistre l'état de référence.
          </EmptyState>
        )}
        <ul className="change-list">
          {(changes.data ?? []).map((c) => <ChangeRow key={c.id} change={c} label={label} onAcknowledge={acknowledge} />)}
        </ul>
      </Panel>
    </div>
  );
}
