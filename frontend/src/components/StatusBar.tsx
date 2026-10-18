import { useEffect, useState } from "react";
import { formatDateTime, formatRelative, RISK_LABEL, riskBand } from "../lib/format";
import { useLive, type LinkStatus } from "../state/live";
import { ui, useUi } from "../state/ui";
import { IconPlan, IconRecenter } from "./Icons";

const LINK_TEXT: Record<LinkStatus, string> = {
  connecting: "Connexion au flux…",
  live: "Flux temps réel",
  polling: "Mode dégradé (HTTP)",
  offline: "Backend injoignable",
};

const VIEW_TITLE = {
  overview: "Jumeau numérique",
  alerts: "Alertes IDS",
  incidents: "Incidents",
  paths: "Chemins d'attaque",
  mitre: "Matrice MITRE ATT&CK",
  timeline: "Historique des scans",
  simulations: "Simulations what-if",
} as const;

function useNow(intervalMs = 5000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export function StatusBar() {
  const status = useLive((s) => s.status);
  const error = useLive((s) => s.error);
  const stats = useLive((s) => s.state?.stats);
  const lastScan = useLive((s) => s.state?.last_scan_at);
  const view = useUi((s) => s.view);
  const planView = useUi((s) => s.planView);
  const replay = useUi((s) => s.replay);
  const simulation = useUi((s) => s.simulation);
  const now = useNow();

  // Posture : pire signal entre le chemin d'attaque le plus fort et l'asset le plus risqué
  const posture = riskBand(Math.max(stats?.max_path_score ?? 0, stats?.max_risk ?? 0));

  return (
    <header className="statusbar">
      <div className="statusbar-title">
        <h1>{VIEW_TITLE[view]}</h1>
        {stats && (
          <span className={`posture posture-${posture}`} title="Pire signal entre le chemin d'attaque le plus fort et l'asset le plus exposé">
            Posture {RISK_LABEL[posture].toLowerCase()}
          </span>
        )}
      </div>

      <div className="statusbar-modes">
        {replay && (
          <div className="mode-banner mode-replay" role="status">
            Relecture du scan du {formatDateTime(replay.captured_at)}
            <button type="button" className="text-button" onClick={() => ui.setReplay(null)}>
              Revenir au direct
            </button>
          </div>
        )}
        {simulation && (
          <div className="mode-banner mode-simulation" role="status">
            Hypothèse affichée : {simulation.name}
            <button type="button" className="text-button" onClick={() => ui.setSimulation(null)}>
              Masquer
            </button>
          </div>
        )}
      </div>

      <div className="statusbar-right">
        <span className="scan-age" title={lastScan ? formatDateTime(lastScan) : undefined}>
          Dernier scan {formatRelative(lastScan, now)}
        </span>
        <span className={`link link-${status}`} title={error ?? undefined}>
          <span className="link-dot" aria-hidden />
          {LINK_TEXT[status]}
        </span>
        <div className="camera-tools" role="group" aria-label="Caméra">
          <button type="button" className="icon-button" onClick={ui.resetCamera} title="Recentrer la vue" aria-label="Recentrer la vue">
            <IconRecenter />
          </button>
          <button
            type="button"
            className={`icon-button${planView ? " is-on" : ""}`}
            onClick={ui.togglePlanView}
            title={planView ? "Revenir à la vue 3D" : "Vue en plan (de dessus)"}
            aria-pressed={planView}
            aria-label="Vue en plan"
          >
            <IconPlan />
          </button>
        </div>
      </div>
    </header>
  );
}
