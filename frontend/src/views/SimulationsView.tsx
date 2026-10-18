import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { AttackPath, Hypothesis, HypothesisType, Simulation, SimulationResult } from "../api/types";
import { EmptyState, ErrorNote, Hops, Panel, Score } from "../components/ui";
import { formatDateTime } from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { requestRefresh, useLive } from "../state/live";
import { ui, type SimulationOverlay } from "../state/ui";

const HYPOTHESES: { type: HypothesisType; label: string; help: string }[] = [
  { type: "asset_compromised", label: "Un actif est compromis", help: "L'attaquant contrôle déjà cet actif : ses liaisons sortantes deviennent plus faciles à exploiter." },
  { type: "new_service_exposed", label: "Un nouveau service est exposé", help: "Un service supplémentaire s'ouvre sur cet actif : son risque et son accessibilité augmentent." },
  { type: "connection_removed", label: "Une liaison est coupée", help: "Une règle de pare-feu supprime cette liaison : quels chemins disparaissent ?" },
];

function describe(h: Hypothesis | null, label: (id: number) => string): string {
  if (!h) return "Hypothèse non appliquée";
  if (h.type === "connection_removed") return `Liaison ${label(h.source_asset_id)} → ${label(h.destination_asset_id)} coupée`;
  return `${h.type === "asset_compromised" ? "Compromission de" : "Nouveau service sur"} ${label(h.asset_id)}`;
}

function overlayFor(name: string, h: Hypothesis, r: SimulationResult): SimulationOverlay {
  return {
    name,
    compromisedAssetId: h.type === "asset_compromised" ? h.asset_id : null,
    exposedAssetId: h.type === "new_service_exposed" ? h.asset_id : null,
    removedLink: h.type === "connection_removed" ? [h.source_asset_id, h.destination_asset_id] : null,
    newPaths: r.new_paths,
    escalatedPaths: r.escalated_paths ?? [],
  };
}

/* Chemins présents avant et absents après (cas d'une liaison coupée) */
function removedPaths(r: SimulationResult): AttackPath[] {
  const after = new Set(r.paths_after.map((p) => p.nodes.join(">")));
  return r.paths_before.filter((p) => !after.has(p.nodes.join(">")));
}

function ResultView({ simulation, label }: { simulation: Simulation; label: (id: number) => string }) {
  const r = simulation.result;
  if (!r) return <p className="muted">Pas de résultat enregistré pour cette simulation.</p>;
  const gone = removedPaths(r);
  const escalated = r.escalated_paths ?? [];
  const delta = r.paths_after_count - r.paths_before_count;

  return (
    <div className="sim-result">
      <div className="sim-compare">
        <div><span className="mono sim-big">{r.paths_before_count}</span><span className="muted">chemins avant</span></div>
        <div><span className="mono sim-big">{r.paths_after_count}</span><span className="muted">chemins après</span></div>
        <div className={delta > 0 ? "is-worse" : delta < 0 ? "is-better" : ""}>
          <span className="mono sim-big">{delta > 0 ? `+${delta}` : delta}</span>
          <span className="muted">écart</span>
        </div>
      </div>

      {r.new_paths.length > 0 && (
        <>
          <h3 className="section-title">Nouveaux chemins ({r.new_paths.length})</h3>
          <ul className="sim-paths">
            {r.new_paths.slice(0, 8).map((p) => (
              <li key={p.nodes.join(">")}><Score value={p.score} band={p.risk} /><Hops path={p} label={label} /></li>
            ))}
          </ul>
        </>
      )}
      {escalated.length > 0 && (
        <>
          <h3 className="section-title">Chemins aggravés ({escalated.length})</h3>
          <ul className="sim-paths">
            {escalated.slice(0, 8).map((p) => (
              <li key={p.nodes.join(">")}>
                <span className="mono num">{p.score_before?.toFixed(1)} → </span>
                <Score value={p.score} band={p.risk} />
                <Hops path={p} label={label} />
              </li>
            ))}
          </ul>
        </>
      )}
      {gone.length > 0 && (
        <>
          <h3 className="section-title">Chemins supprimés ({gone.length})</h3>
          <ul className="sim-paths">
            {gone.slice(0, 8).map((p) => (
              <li key={p.nodes.join(">")}><Score value={p.score} band={p.risk} /><Hops path={p} label={label} /></li>
            ))}
          </ul>
        </>
      )}
      {r.new_paths.length === 0 && escalated.length === 0 && gone.length === 0 && (
        <EmptyState title="Aucun effet mesurable">Cette hypothèse ne change aucun chemin d'attaque vers les cibles à forte valeur.</EmptyState>
      )}
    </div>
  );
}

export function SimulationsView() {
  const simulations = useResource(() => api.simulations(), []);
  const links = useLive((s) => s.state?.links);
  const { list: assets, label } = useAssetIndex();

  const [type, setType] = useState<HypothesisType>("asset_compromised");
  const [assetId, setAssetId] = useState<number | "">("");
  const [linkKey, setLinkKey] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<number | null>(null);

  useEffect(() => () => ui.setSimulation(null), []);

  const open = useMemo(() => simulations.data?.find((s) => s.id === openId) ?? null, [simulations.data, openId]);

  const show = (sim: Simulation) => {
    setOpenId(sim.id);
    if (sim.hypothesis && sim.result) ui.setSimulation(overlayFor(sim.name, sim.hypothesis, sim.result));
    else ui.setSimulation(null);
  };

  const hypothesis = (): Hypothesis | null => {
    if (type === "connection_removed") {
      const [s, d] = linkKey.split(">").map(Number);
      return linkKey ? { type, source_asset_id: s, destination_asset_id: d } : null;
    }
    return assetId === "" ? null : { type, asset_id: assetId };
  };

  const run = async (event: FormEvent) => {
    event.preventDefault();
    const h = hypothesis();
    if (!h) {
      setError(type === "connection_removed" ? "Choisissez la liaison à couper." : "Choisissez l'actif concerné.");
      return;
    }
    setRunning(true);
    setError(null);
    try {
      const name = describe(h, label);
      const sim = await api.createSimulation(name, HYPOTHESES.find((x) => x.type === type)?.help);
      await api.applyHypothesis(sim.id, h);
      const { result } = await api.simulationResult(sim.id);
      setOpenId(sim.id);
      ui.setSimulation(overlayFor(name, h, result));
      simulations.reload();
      requestRefresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const current = HYPOTHESES.find((h) => h.type === type)!;

  return (
    <div className="layout-split">
      <div className="stack">
        <Panel title="Nouvelle hypothèse" meta="Calculée sur une copie du graphe : aucune donnée réelle n'est modifiée">
          <form className="sim-form" onSubmit={run}>
            <fieldset className="choice-group">
              <legend className="visually-hidden">Type d'hypothèse</legend>
              {HYPOTHESES.map((h) => (
                <label key={h.type} className={`choice${type === h.type ? " is-on" : ""}`}>
                  <input type="radio" name="hypothesis" value={h.type} checked={type === h.type} onChange={() => setType(h.type)} />
                  {h.label}
                </label>
              ))}
            </fieldset>
            <p className="muted small">{current.help}</p>

            {type === "connection_removed" ? (
              <label className="field">
                <span>Liaison</span>
                <select className="input" value={linkKey} onChange={(e) => setLinkKey(e.target.value)}>
                  <option value="">Choisir une liaison active…</option>
                  {(links ?? []).map((l) => (
                    <option key={`${l.source}>${l.target}`} value={`${l.source}>${l.target}`}>
                      {label(l.source)} → {label(l.target)} (poids {l.weight.toFixed(0)})
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label className="field">
                <span>Actif</span>
                <select className="input" value={assetId} onChange={(e) => setAssetId(e.target.value === "" ? "" : Number(e.target.value))}>
                  <option value="">Choisir un actif…</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>{a.ip}{a.hostname && a.hostname !== a.ip ? ` — ${a.hostname}` : ""}</option>
                  ))}
                </select>
              </label>
            )}

            {error && <ErrorNote message={error} />}
            <button type="submit" className="primary-button" disabled={running}>
              {running ? "Simulation en cours…" : "Lancer la simulation"}
            </button>
          </form>
        </Panel>

        <Panel className="panel-fill" title="Simulations précédentes" meta={simulations.data ? `${simulations.data.length} enregistrée${simulations.data.length > 1 ? "s" : ""}` : "Chargement…"}>
          {simulations.error && <ErrorNote message={simulations.error} onRetry={simulations.reload} />}
          {simulations.data?.length === 0 && <EmptyState title="Aucune simulation">Formulez une première hypothèse ci-dessus.</EmptyState>}
          <ul className="sim-list">
            {(simulations.data ?? []).map((s) => (
              <li key={s.id}>
                <button type="button" className={`sim-row${s.id === openId ? " is-selected" : ""}`} aria-pressed={s.id === openId} onClick={() => show(s)}>
                  <span className="sim-name">{s.hypothesis ? describe(s.hypothesis, label) : s.name}</span>
                  <span className="muted">{formatDateTime(s.completed_at ?? s.created_at)}</span>
                  {s.result && (
                    <span className="mono num">
                      {s.result.paths_before_count} → {s.result.paths_after_count}
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {open && (
        <Panel
          className="detail"
          title={open.hypothesis ? describe(open.hypothesis, label) : open.name}
          meta={`Simulation #${open.id} · ${formatDateTime(open.completed_at ?? open.created_at)}`}
          onClose={() => { setOpenId(null); ui.setSimulation(null); }}
        >
          <ResultView simulation={open} label={label} />
          <p className="muted small">Les chemins nouveaux ou aggravés sont tracés en violet pointillé dans la scène.</p>
        </Panel>
      )}
    </div>
  );
}
