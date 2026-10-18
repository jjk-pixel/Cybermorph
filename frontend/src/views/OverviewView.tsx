import { useMemo } from "react";
import { EmptyState, EvidenceTag, Hops, Panel, PriorityTag, RiskTag, Score, Stat } from "../components/ui";
import { ASSET_TYPE_LABEL, formatCount, formatTime, priorityBand, riskBand } from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";

/* Jauge circulaire du risque moyen ; le second arc montre le pire asset. */
function RiskDial({ avg, max }: { avg: number; max: number }) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const arc = (v: number) => `${(Math.min(v, 100) / 100) * c * 0.75} ${c}`;
  return (
    <svg className="dial" viewBox="0 0 120 120" role="img" aria-label={`Risque moyen ${avg.toFixed(1)} sur 100, maximum ${max.toFixed(1)}`}>
      <g transform="rotate(135 60 60)">
        <circle cx="60" cy="60" r={r} className="dial-track" strokeDasharray={arc(100)} />
        <circle cx="60" cy="60" r={r} className={`dial-max dial-${riskBand(max)}`} strokeDasharray={arc(max)} />
        <circle cx="60" cy="60" r={r - 9} className={`dial-avg dial-${riskBand(avg)}`} strokeDasharray={`${(Math.min(avg, 100) / 100) * 2 * Math.PI * (r - 9) * 0.75} ${c}`} />
      </g>
      <text x="60" y="62" className="dial-value">{avg.toFixed(0)}</text>
      <text x="60" y="80" className="dial-caption">risque moyen</text>
    </svg>
  );
}

function Legend() {
  return (
    <div className="legend" aria-label="Légende de la scène">
      <div className="legend-group">
        <span className="legend-swatch sw-cyan" /> Trafic observé
        <span className="legend-swatch sw-blue sw-dashed" /> Voisinage ARP
        <span className="legend-swatch sw-amber" /> Corroboré IDS
      </div>
      <div className="legend-group">
        <span className="legend-swatch sw-violet" /> Chemin prédit
        <span className="legend-swatch sw-red" /> Incident
      </div>
      <div className="legend-group legend-note">Anneau = rôle · altitude et auréole = score de risque</div>
    </div>
  );
}

export function OverviewView() {
  const live = useLive((s) => s.state);
  const selectedId = useUi((s) => s.selectedAssetId);
  const { label } = useAssetIndex();

  const ranked = useMemo(
    () => [...(live?.assets ?? [])].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)),
    [live?.assets],
  );

  if (!live) return null;
  const { stats } = live;
  const top = live.attack_paths[0];

  return (
    <div className="layout-overview">
      <div className="column column-left">
        <Panel title="Posture du réseau" meta={`${stats.assets_up} en ligne · ${stats.assets_down} hors ligne`}>
          <div className="posture-block">
            <RiskDial avg={stats.avg_risk} max={stats.max_risk} />
            <div className="stat-grid">
              <Stat label="Actifs" value={stats.assets} />
              <Stat label="Liaisons actives" value={stats.connections} />
              <Stat label="Alertes 24 h" value={formatCount(stats.alerts_24h)} tone={stats.alerts_24h ? "moderate" : undefined} />
              <Stat label="Incidents actifs" value={stats.active_incidents} tone={stats.active_incidents ? "critical" : undefined} />
            </div>
          </div>
        </Panel>

        <Panel
          title="Chemin le plus probable"
          meta={`${stats.attack_paths} chemin${stats.attack_paths > 1 ? "s" : ""} au-dessus de 25`}
          actions={
            stats.attack_paths > 1 && (
              <button type="button" className="text-button" onClick={() => ui.setView("paths")}>
                Tous les chemins
              </button>
            )
          }
        >
          {top ? (
            <div className="top-path">
              <div className="top-path-score">
                <Score value={top.score} band={top.risk} />
                <RiskTag band={top.risk} />
                <EvidenceTag level={top.evidence_level} />
              </div>
              <Hops path={top} label={label} />
              <p className="muted small">
                {top.hops} saut{top.hops > 1 ? "s" : ""} vers une cible à forte valeur. Tracé en violet dans la scène.
              </p>
            </div>
          ) : (
            <EmptyState title="Aucun chemin significatif">Aucun enchaînement ne dépasse un score de 25.</EmptyState>
          )}
        </Panel>
      </div>

      <div className="column column-center">
        <Legend />
        <Panel className="alert-stream" title="Alertes en direct" meta={`${formatCount(stats.alerts_total)} enregistrées`}
          actions={<button type="button" className="text-button" onClick={() => ui.setView("alerts")}>Ouvrir</button>}
        >
          {live.recent_alerts.length === 0 ? (
            <EmptyState title="Aucune alerte reçue">Suricata n'a encore rien signalé.</EmptyState>
          ) : (
            <ul className="stream">
              {live.recent_alerts.slice(0, 6).map((a) => (
                <li key={a.id} className={`stream-row band-${priorityBand(a.priority)}`}>
                  <span className="mono stream-time">{formatTime(a.last_seen)}</span>
                  <PriorityTag priority={a.priority} />
                  <span className="stream-msg" title={a.message}>{a.message}</span>
                  <button
                    type="button"
                    className="link-button mono stream-pair"
                    onClick={() => a.source_asset_id != null && ui.selectAsset(a.source_asset_id)}
                    disabled={a.source_asset_id == null}
                  >
                    {a.source_ip} → {a.destination_ip}
                  </button>
                  <span className="mono stream-count">×{formatCount(a.occurrence_count)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="column column-right">
        {selectedId == null && (
          <Panel title="Actifs par niveau de risque" meta="Sélectionnez un actif pour l'inspecter">
            <ul className="asset-list">
              {ranked.map((a) => (
                <li key={a.id}>
                  <button type="button" className="asset-row" onClick={() => ui.selectAsset(a.id)}>
                    <span className={`asset-dot band-${a.status === "down" ? "down" : riskBand(a.risk_score)}`} aria-hidden />
                    <span className="mono asset-ip">{a.ip}</span>
                    <span className="asset-kind">
                      {a.hostname && a.hostname !== a.ip ? a.hostname : ASSET_TYPE_LABEL[a.asset_type] ?? a.asset_type}
                    </span>
                    <Score value={a.risk_score} />
                  </button>
                </li>
              ))}
            </ul>
          </Panel>
        )}
      </div>
    </div>
  );
}
