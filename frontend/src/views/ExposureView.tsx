import { useEffect, useMemo } from "react";
import { api } from "../api/client";
import type { Criticality, Recommendation } from "../api/types";
import { EmptyState, ErrorNote, Meter, Panel, Score, Stat } from "../components/ui";
import { CriticalityTag } from "../components/CriticalityTag";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";

const recommendationKey = (r: Recommendation) =>
  r.kind === "edge" ? `e${r.source_asset_id}>${r.destination_asset_id}` : `n${r.asset_id}`;

const recommendationNodes = (r: Recommendation) =>
  r.kind === "edge" ? [r.source_asset_id!, r.destination_asset_id!] : [r.asset_id!];

/* Exposition : où couper pour protéger les actifs critiques, chiffré sur le modèle. */
export function ExposureView() {
  const lastScan = useLive((s) => s.state?.last_scan_at);
  // Une déclaration de criticité change les cibles : on recalcule quand elle change
  const criticalitySignature = useLive((s) =>
    (s.state?.assets ?? []).map((a) => `${a.id}:${a.criticality.level}:${a.criticality.source}`).join(","),
  );
  const exposure = useResource(() => api.exposure(), [lastScan, criticalitySignature]);
  const highlight = useUi((s) => s.highlight);
  const { label } = useAssetIndex();

  useEffect(() => () => ui.highlight(null), []);

  const highlightKey = highlight?.nodes.join(">");
  const data = exposure.data;
  const unreached = useMemo(() => data?.targets.filter((t) => t.paths === 0) ?? [], [data]);

  if (exposure.error && !data) return <div className="layout-split"><Panel title="Exposition"><ErrorNote message={exposure.error} onRetry={exposure.reload} /></Panel></div>;
  if (!data) return <div className="layout-split"><Panel title="Exposition"><p className="muted">Calcul de l'exposition…</p></Panel></div>;

  const { summary } = data;

  return (
    <div className="layout-split layout-exposure">
      <Panel
        className="panel-fill"
        title="Exposition des actifs critiques"
        meta={`${summary.paths} chemin${summary.paths > 1 ? "s" : ""} au-dessus de ${data.parameters.min_score}, ${data.parameters.max_length} sauts au plus`}
      >
        <div className="stat-grid">
          <Stat label="Cibles atteintes" value={`${summary.targets_reached} / ${summary.targets}`} tone={summary.targets_reached ? "high" : undefined} />
          <Stat label="Score max d'un chemin" value={summary.max_score.toFixed(1)} />
          <Stat label="Entrées qualifiées" value={summary.qualified_entry_points} />
          <Stat label="Chemins depuis une entrée qualifiée" value={summary.paths_from_qualified_entries} tone={summary.paths_from_qualified_entries ? "moderate" : undefined} />
        </div>

        <h3 className="section-title">Mesures les plus efficaces</h3>
        {data.recommendations.length === 0 ? (
          <EmptyState title="Aucune mesure à proposer">Aucun chemin ne dépasse le seuil : rien à couper pour l'instant.</EmptyState>
        ) : (
          <ol className="reco-list">
            {data.recommendations.map((r) => {
              const nodes = recommendationNodes(r);
              const active = highlightKey === nodes.join(">");
              return (
                <li key={recommendationKey(r)}>
                  <button
                    type="button"
                    className={`reco-row${active ? " is-selected" : ""}`}
                    aria-pressed={active}
                    onClick={() => ui.highlight(active ? null : { nodes })}
                  >
                    <span className="reco-action">{r.action}</span>
                    <span className="reco-impact">
                      <Meter value={r.score_reduction_pct} band="critical" label="Réduction du score d'exposition" />
                      <span className="mono num">−{r.score_reduction_pct.toFixed(0)} %</span>
                    </span>
                    <span className="reco-meta">
                      {r.paths_removed} chemin{r.paths_removed > 1 ? "s" : ""} supprimé{r.paths_removed > 1 ? "s" : ""}
                      {r.targets_protected.length > 0 && <> · protège {r.targets_protected.map(label).join(", ")}</>}
                      {" · "}score max ensuite <span className="mono">{r.max_score_after.toFixed(1)}</span>
                    </span>
                    <span className="reco-why">{r.rationale}</span>
                  </button>
                </li>
              );
            })}
          </ol>
        )}

        <h3 className="section-title">Points de blocage</h3>
        {data.choke_points.length === 0 ? (
          <p className="muted small">
            Aucun actif intermédiaire n'est partagé par plusieurs chemins : les chemins actuels sont directs ou indépendants,
            si bien que protéger un seul actif de passage n'en couperait pas plusieurs à la fois.
          </p>
        ) : (
          <ul className="choke-list">
            {data.choke_points.map((c) => (
              <li key={c.asset_id}>
                <button type="button" className="asset-row" onClick={() => ui.selectAsset(c.asset_id)}>
                  <span className="choke-mark" aria-hidden />
                  <span className="mono asset-ip">{label(c.asset_id)}</span>
                  <span className="asset-kind">
                    {c.paths} chemins ({Math.round(c.share * 100)} %) vers {c.targets.map(label).join(", ")}
                  </span>
                  <Score value={c.max_score} />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel className="panel-fill" title="Cibles et points d'entrée" meta="Une entrée n'est qualifiée que par un fait observé">
        <h3 className="section-title">Actifs critiques</h3>
        <ul className="target-list">
          {data.targets.map((t) => (
            <li key={t.asset_id}>
              <button type="button" className="asset-row" onClick={() => ui.selectAsset(t.asset_id)}>
                <span className="mono asset-ip">{label(t.asset_id)}</span>
                <CriticalityTag criticality={t.criticality as Criticality} />
                <span className="asset-kind">
                  {t.paths === 0 ? "aucun chemin" : `${t.paths} chemin${t.paths > 1 ? "s" : ""}`}
                </span>
                {t.paths > 0 ? <Score value={t.max_score} /> : <span className="muted">—</span>}
              </button>
            </li>
          ))}
        </ul>
        {unreached.length > 0 && (
          <p className="muted small">
            Sans chemin au-dessus du seuil : {unreached.map((t) => label(t.asset_id)).join(", ")}.
          </p>
        )}

        <h3 className="section-title">Points d'entrée qualifiés</h3>
        {data.entry_points.length === 0 ? (
          <p className="muted small">Aucun fait ne qualifie un point d'entrée : les chemins supposent un actif interne compromis.</p>
        ) : (
          <ul className="entry-list">
            {data.entry_points.map((e) => (
              <li key={e.asset_id}>
                <button type="button" className="link-button mono" onClick={() => ui.selectAsset(e.asset_id)}>{label(e.asset_id)}</button>
                <span className="muted small">{e.paths} chemin{e.paths > 1 ? "s" : ""}</span>
                <ul className="entry-facts">
                  {e.facts.map((f) => (
                    <li key={f.kind}>
                      <span className={`entry-kind entry-${f.kind}`}>{f.label}</span>
                      {f.detail && <span className="muted"> · {f.detail}</span>}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}

        <h3 className="section-title">Hypothèses du calcul</h3>
        <ul className="assumptions">
          {data.assumptions.map((a) => <li key={a}>{a}</li>)}
        </ul>
      </Panel>
    </div>
  );
}
