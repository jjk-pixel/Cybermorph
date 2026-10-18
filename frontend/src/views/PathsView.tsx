import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AttackPath } from "../api/types";
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
                    <EvidenceTag level={p.evidence_level} />
                    <span className="muted">{p.hops} saut{p.hops > 1 ? "s" : ""}</span>
                    {p.alert_evidence && p.alert_evidence.length > 0 && (
                      <span className="muted" title={p.alert_evidence.map((a) => a.message).join("\n")}>
                        {p.alert_evidence.length} corroboration{p.alert_evidence.length > 1 ? "s" : ""} IDS
                      </span>
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
        <p className="muted small">
          Score = moyenne des poids de transition (accessibilité, service exposé, risque et rôle de la cible, preuve), pénalisée de 15 % par saut supplémentaire.
          Le niveau de preuve est celui du maillon le plus faible.
        </p>
      </Panel>
    </div>
  );
}
