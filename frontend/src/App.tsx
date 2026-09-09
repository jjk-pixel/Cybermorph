import { useState } from "react";
import { useLiveState, type Asset } from "./hooks/useLiveState";
import { useSimulation } from "./hooks/useSimulation";
import NetworkGraph from "./components/NetworkGraph";
import Sidebar, { type ViewName } from "./components/Sidebar";
import { AlertsView, PathsView, MitreView, TimelineView } from "./components/ListViews";

function riskLabel(score: number) {
  if (score >= 75) return { label: "CRITIQUE", color: "#C1443D" };
  if (score >= 50) return { label: "ÉLEVÉ", color: "#E0793E" };
  if (score >= 25) return { label: "MODÉRÉ", color: "#E8A33D" };
  return { label: "FAIBLE", color: "#4CAF7D" };
}

function View3D() {
  const { state, connected } = useLiveState();
  const [selected, setSelected] = useState<Asset | null>(null);
  const { result: simResult, loading: simLoading, compromisedAssetId, runCompromise, clear: clearSim } = useSimulation();

  if (!state) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" }}>
        <p className="mono" style={{ color: "#7C8798" }}>Connexion à CYBERMORPH...</p>
      </div>
    );
  }

  const relatedPaths = selected
    ? state.attack_paths.filter((p) => p.source === selected.id || p.target === selected.id)
    : [];

  return (
    <>
      <div className="hud-title">
        <h1>CYBERMORPH</h1>
        <p>
          <span className={`connection-dot ${connected ? "" : "offline"}`} />
          {connected ? "flux temps réel actif" : "reconnexion..."} · {state.assets.length} actifs · {state.attack_paths.length} chemins
        </p>
      </div>

      <NetworkGraph
        assets={state.assets}
        edges={state.edges}
        attackPaths={state.attack_paths}
        activeIncidents={state.active_incidents}
        onSelect={setSelected}
        selectedId={selected?.id}
        simulatedPaths={[...(simResult?.new_paths || []), ...(simResult?.strengthened_paths || [])]}
        compromisedAssetId={compromisedAssetId}
      />

      {simResult && (
        <div className="sim-banner">
          Simulation active — {simResult.new_paths_count} nouveau(x) chemin(s), {simResult.strengthened_paths?.length || 0} chemin(s) renforcé(s)
          <button onClick={clearSim}>Terminer la simulation</button>
        </div>
      )}

      {selected && (
        <div className="panel">
          <button className="close-btn" onClick={() => setSelected(null)}>×</button>
          <h2 className="mono">{selected.hostname || selected.ip}</h2>
          <p className="tactic">{selected.asset_type.toUpperCase()}</p>

          <div className="field">
            <label>ADRESSE IP</label>
            <div className="value">{selected.ip}</div>
          </div>

          <div className="field">
            <label>STATUT</label>
            <div className="value">{selected.status}</div>
          </div>

          <div className="field">
            <label>NIVEAU DE RISQUE</label>
            <div>
              <span
                className="risk-badge"
                style={{
                  background: `${riskLabel(selected.risk_score).color}22`,
                  color: riskLabel(selected.risk_score).color,
                }}
              >
                {selected.risk_score.toFixed(1)} — {riskLabel(selected.risk_score).label}
              </span>
            </div>
          </div>

          <button
            className="sim-btn"
            disabled={simLoading}
            onClick={() => runCompromise(selected.id)}
          >
            {simLoading ? "Simulation en cours..." : "🧪 Simuler la compromission de cet asset"}
          </button>

          {relatedPaths.length > 0 && (
            <div className="field" style={{ marginTop: 18 }}>
              <label>CHEMINS D'ATTAQUE ASSOCIÉS</label>
              {relatedPaths.map((p, i) => (
                <div className="path-row" key={i}>
                  <div className="mono score">{p.score.toFixed(1)} — {p.risk}</div>
                  <div style={{ color: "#7C8798", fontSize: 11, marginTop: 2 }}>
                    preuve : {p.evidence_level}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default function App() {
  const [view, setView] = useState<ViewName>("3d");

  return (
    <div className="app-layout">
      <Sidebar current={view} onChange={setView} />
      <div className="main-view">
        {view === "3d" && <View3D />}
        {view === "alerts" && <AlertsView />}
        {view === "paths" && <PathsView />}
        {view === "mitre" && <MitreView />}
        {view === "timeline" && <TimelineView />}
      </div>
    </div>
  );
}
