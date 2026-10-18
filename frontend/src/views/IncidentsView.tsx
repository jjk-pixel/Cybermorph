import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { IncidentStep } from "../api/types";
import { EmptyState, ErrorNote, Panel } from "../components/ui";
import { formatDateTime, formatRelative, INCIDENT_STATUS_LABEL } from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { useLive } from "../state/live";
import { ui } from "../state/ui";

type Filter = "active" | "all";

const NO_STEPS: IncidentStep[] = [];

function StepList({ steps, label }: { steps: IncidentStep[]; label: (id: number) => string }) {
  const bySequence = useMemo(() => {
    const groups = new Map<number, IncidentStep[]>();
    for (const s of steps) groups.set(s.sequence, [...(groups.get(s.sequence) ?? []), s]);
    return [...groups.entries()].sort((a, b) => a[0] - b[0]);
  }, [steps]);

  if (steps.length === 0) return <p className="muted">Aucune étape de propagation n'a encore été évaluée.</p>;

  return (
    <ol className="steps">
      {bySequence.map(([sequence, group]) => (
        <li key={sequence} className="step-group">
          <span className="step-index mono">Étape {sequence}</span>
          <ul>
            {group.map((s) => (
              <li key={`${s.source_asset_id}-${s.destination_asset_id}`} className={`step step-${s.status}`}>
                <span className="mono">{label(s.source_asset_id)} → {label(s.destination_asset_id)}</span>
                <span className="step-status">{s.status === "confirmed" ? "Confirmée" : "Possible"}</span>
                <span className="mono num">{Math.round(s.confidence * 100)} %</span>
                {s.technique_id && <span className="mono technique">{s.technique_id}</span>}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}

export function IncidentsView() {
  const liveIncidents = useLive((s) => s.state?.active_incidents);
  const history = useResource(() => api.incidents(), [], 30_000);
  const { label } = useAssetIndex();
  const [filter, setFilter] = useState<Filter>("active");
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const list = useMemo(() => {
    const all = history.data ?? [];
    return filter === "active" ? all.filter((i) => i.status === "detected" || i.status === "progressing") : all;
  }, [history.data, filter]);

  const detail = useResource(() => (selectedId != null ? api.incident(selectedId) : Promise.resolve(null)), [selectedId]);
  // Les incidents actifs sont aussi dans le flux live : on suit leurs étapes en temps réel
  const liveDetail = liveIncidents?.find((i) => i.incident_id === selectedId);
  const steps = liveDetail?.steps ?? detail.data?.steps ?? NO_STEPS;
  const current = liveDetail?.current_asset_id ?? detail.data?.current_asset_id ?? null;

  useEffect(() => {
    if (selectedId == null) {
      ui.focusIncident(null);
      return;
    }
    ui.focusIncident({ id: selectedId, steps, currentAssetId: current });
  }, [selectedId, steps, current]);

  useEffect(() => () => ui.focusIncident(null), []);

  const selected = list.find((i) => i.id === selectedId) ?? (detail.data && detail.data.id === selectedId ? detail.data : undefined);

  return (
    <div className="layout-split">
      <Panel
        className="panel-fill"
        title="Incidents"
        meta={history.data ? `${list.length} ${filter === "active" ? "actif" : "au total"}${list.length > 1 ? "s" : ""}` : "Chargement…"}
        actions={
          <div className="segmented" role="group" aria-label="Filtrer les incidents">
            <button type="button" className={filter === "active" ? "is-on" : ""} aria-pressed={filter === "active"} onClick={() => setFilter("active")}>Actifs</button>
            <button type="button" className={filter === "all" ? "is-on" : ""} aria-pressed={filter === "all"} onClick={() => setFilter("all")}>Tous</button>
          </div>
        }
      >
        {history.error && <ErrorNote message={history.error} onRetry={history.reload} />}
        {history.data && list.length === 0 && (
          <EmptyState title={filter === "active" ? "Aucun incident actif" : "Aucun incident enregistré"}>
            Un incident s'ouvre lorsqu'une alerte de priorité 1 ou 2 décrit une attaque (scan, exploit, brute force…).
          </EmptyState>
        )}
        <ul className="incident-list">
          {list.map((i) => (
            <li key={i.id}>
              <button
                type="button"
                className={`incident-row status-${i.status}${i.id === selectedId ? " is-selected" : ""}`}
                aria-pressed={i.id === selectedId}
                onClick={() => setSelectedId(i.id === selectedId ? null : i.id)}
              >
                <span className="incident-id mono">#{i.id}</span>
                <span className="incident-flow mono">{label(i.source_asset_id)} → {label(i.current_asset_id)}</span>
                <span className="incident-status">{INCIDENT_STATUS_LABEL[i.status] ?? i.status}</span>
                <span className="incident-progress mono">{i.current_step}/{Math.max(i.total_steps, i.current_step)}</span>
                <span className="incident-age">{formatRelative(i.last_seen)}</span>
              </button>
            </li>
          ))}
        </ul>
      </Panel>

      {selected && (
        <Panel
          className="detail"
          title={`Incident #${selected.id}`}
          meta={`${INCIDENT_STATUS_LABEL[selected.status] ?? selected.status} · ouvert le ${formatDateTime(selected.started_at)}`}
          onClose={() => setSelectedId(null)}
        >
          {liveDetail?.trigger && <p className="trigger">Déclencheur : {liveDetail.trigger}</p>}
          <dl className="facts">
            <dt>Origine</dt>
            <dd className="mono">{label(selected.source_asset_id)}</dd>
            <dt>Position actuelle</dt>
            <dd className="mono">{label(selected.current_asset_id)}</dd>
            <dt>Cible initiale</dt>
            <dd className="mono">{label(selected.target_asset_id)}</dd>
            <dt>Technique</dt>
            <dd className="mono">{selected.technique_id ?? "non déterminée"}</dd>
            <dt>Confiance</dt>
            <dd className="mono">{Math.round((selected.confidence ?? 0) * 100)} %</dd>
            <dt>Dernière activité</dt>
            <dd>{formatDateTime(selected.last_seen)}</dd>
          </dl>
          <h3 className="section-title">Propagation</h3>
          {detail.error && <ErrorNote message={detail.error} onRetry={detail.reload} />}
          <StepList steps={steps} label={label} />
          <p className="muted small">
            Une étape est confirmée quand une alerte IDS montre l'asset compromis attaquant la destination. Sans activité pendant une heure, l'incident passe en dormant.
          </p>
        </Panel>
      )}
    </div>
  );
}
