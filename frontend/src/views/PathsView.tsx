import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AttackPath, PathLimits } from "../api/types";
import { formatConfidence, PRECONDITION_LABEL } from "../lib/format";
import { EmptyState, ErrorNote, EvidenceTag, Hops, Meter, Panel, RiskTag, Score } from "../components/ui";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";

const pathKey = (p: AttackPath) => p.nodes.join(">");

export function PathsView() {
  const [minScore, setMinScore] = useState(25);
  const [maxLength, setMaxLength] = useState(4);
  // Recalcul quand le flux live change (nouveau scan), ou quand les paramètres changent
  const generatedAt = useLive((s) => s.state?.last_scan_at);
  const paths = useResource(() => api.attackPaths(minScore, maxLength), [minScore, maxLength, generatedAt]);
  const focus = useUi((s) => s.focusPath);
  const { label } = useAssetIndex();

  useEffect(() => () => ui.focusPath(null), []);

  const list = paths.data?.paths ?? [];
  const focusKey = focus ? pathKey(focus) : null;

  return (
    <div className="layout-split">
      <Panel
        className="panel-fill"
        title="Chemins d'attaque"
        meta={paths.data ? `${paths.data.count} chemin${paths.data.count > 1 ? "s" : ""} vers des cibles à forte valeur` : "Calcul…"}
      >
        <div className="controls">
          <label className="control">
            <span>Score minimal <span className="mono">{minScore}</span></span>
            <input type="range" min={0} max={90} step={5} value={minScore} onChange={(e) => setMinScore(Number(e.target.value))} />
          </label>
          <label className="control">
            <span>Sauts maximum <span className="mono">{maxLength}</span></span>
            <input type="range" min={1} max={6} step={1} value={maxLength} onChange={(e) => setMaxLength(Number(e.target.value))} />
          </label>
        </div>

        {paths.error && <ErrorNote message={paths.error} onRetry={paths.reload} />}
        {paths.data && list.length === 0 && (
          <EmptyState title="Aucun chemin à ce seuil">Baissez le score minimal pour voir les enchaînements moins probables.</EmptyState>
        )}

        <ul className="path-list">
          {list.map((p) => {
            const key = pathKey(p);
            const active = key === focusKey;
            return (
              <li key={key}>
                <button
                  type="button"
                  className={`path-row${active ? " is-selected" : ""}`}
                  aria-pressed={active}
                  onClick={() => ui.focusPath(active ? null : p)}
                >
                  <div className="path-row-head">
                    <Score value={p.score} band={p.risk} />
                    <Meter value={p.score} band={p.risk} label="Score du chemin" />
                    <RiskTag band={p.risk} />
                  </div>
                  <Hops path={p} label={label} />
                  <div className="path-row-foot">
                    {p.nature && (
                      <span className={`nature-tag nature-${p.nature}`} title={p.nature === "observed"
                        ? "Chaque saut est corroboré par une alerte IDS offensive (P1-P2)"
                        : "Chemin possible sur le modèle, sans activité hostile observée à chaque saut"}>
                        {p.nature === "observed" ? "Observé" : "Hypothétique"}
                      </span>
                    )}
                    <EvidenceTag level={p.evidence_level} />
                    {p.confidence != null && <span className="muted">confiance {formatConfidence(p.confidence)}</span>}
                    <span className="muted">{p.hops} saut{p.hops > 1 ? "s" : ""}</span>
                    {p.alert_evidence && p.alert_evidence.length > 0 && (
                      <span className="muted" title={p.alert_evidence.map((a) => a.message).join("\n")}>
                        {p.alert_evidence.length} corroboration{p.alert_evidence.length > 1 ? "s" : ""} IDS
                      </span>
                    )}
                  </div>
                </button>
                {active && p.steps && <PathSteps path={p} label={label} />}
              </li>
            );
          })}
        </ul>
        {paths.data?.limits && <Limits limits={paths.data.limits} label={label} />}
        <p className="muted small">
          Score = moyenne des poids de transition (accessibilité, service exposé, risque et rôle de la cible, preuve), pénalisée de 15 % par saut supplémentaire.
          Le niveau de preuve et la confiance sont ceux du maillon le plus faible. Un saut n'est retenu que si un service de la cible est atteignable ;
          {" "}{paths.data?.note ?? "ces chemins sont des analyses défensives, pas des exploitations démontrées."}
        </p>
      </Panel>
    </div>
  );
}

function PathSteps({ path, label }: { path: AttackPath; label: (id: number) => string }) {
  return (
    <ol className="path-steps" aria-label="Préconditions de chaque saut">
      {path.steps!.map((step) => (
        <li key={`${step.source}>${step.target}`}>
          <div className="path-step-head">
            <span className="mono">{label(step.source)} → {label(step.target)}</span>
            {step.services && step.services.length > 0 && <span className="muted small">services {step.services.join(", ")}</span>}
            {step.confidence != null && <span className="muted small">confiance {formatConfidence(step.confidence)}</span>}
          </div>
          <ul className="preconditions">
            {(step.preconditions ?? []).map((c) => (
              <li key={c.condition} className={`precondition is-${c.status}`}>
                <span className="precondition-status">{PRECONDITION_LABEL[c.status] ?? c.status}</span>
                <span>{c.condition}</span>
                <span className="muted small">{c.evidence}</span>
              </li>
            ))}
          </ul>
          {step.uncertainties && step.uncertainties.length > 0 && (
            <p className="muted small">Incertitudes : {step.uncertainties.join(" ; ")}.</p>
          )}
        </li>
      ))}
    </ol>
  );
}

function Limits({ limits, label }: { limits: PathLimits; label: (id: number) => string }) {
  const truncated = limits.truncated_pairs.length > 0 || limits.total_limit_reached;
  if (!truncated && limits.excluded_transitions.length === 0) return null;
  return (
    <div className="path-limits">
      {limits.excluded_transitions.length > 0 && (
        <p className="small">
          {limits.excluded_transitions.length} relation{limits.excluded_transitions.length > 1 ? "s" : ""} écartée{limits.excluded_transitions.length > 1 ? "s" : ""} faute de service atteignable connu :{" "}
          <span className="mono">{limits.excluded_transitions.map((e) => `${label(e.source)} → ${label(e.target)}`).join(", ")}</span>.
        </p>
      )}
      {truncated && (
        <p className="small">
          Calcul borné : {limits.max_paths_per_pair} chemins par paire, {limits.max_total_paths} au total, {limits.max_length} sauts au plus.
          {limits.total_limit_reached ? " La limite totale a été atteinte : la liste n'est pas exhaustive." : ` ${limits.truncated_pairs.length} paire(s) tronquée(s).`}
        </p>
      )}
    </div>
  );
}
