import { useMemo } from "react";
import {
  ASSET_TYPE_LABEL, EVIDENCE_LABEL, formatRelative, RISK_BREAKDOWN_LABEL, RISK_BREAKDOWN_MAX, riskBand, splitList,
} from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";
import { AssetProfile } from "./AssetProfile";
import { Meter, Panel, PriorityTag, RiskTag, Score } from "./ui";

/* Fiche de l'asset sélectionné dans la scène : identité, exposition, explication du score, relations. */
export function AssetInspector() {
  const selectedId = useUi((s) => s.selectedAssetId);
  const live = useLive((s) => s.state);
  const { byId, label } = useAssetIndex();
  const asset = selectedId != null ? byId.get(selectedId) : undefined;

  const related = useMemo(() => {
    if (!asset || !live) return null;
    return {
      outgoing: live.links.filter((l) => l.source === asset.id),
      incoming: live.links.filter((l) => l.target === asset.id),
      alerts: live.recent_alerts.filter((a) => a.source_ip === asset.ip || a.destination_ip === asset.ip).slice(0, 5),
      paths: live.attack_paths.filter((p) => p.nodes.includes(asset.id)),
      incidents: live.active_incidents.filter((i) => [i.source_asset_id, i.current_asset_id, i.target_asset_id].includes(asset.id)),
    };
  }, [asset, live]);

  if (!asset || !related) return null;

  const ports = splitList(asset.open_ports);
  const services = splitList(asset.services);
  const breakdown = asset.risk_factors?.breakdown ?? {};

  return (
    <Panel
      className="inspector"
      title={<span className="mono">{asset.ip}</span>}
      meta={
        <>
          {asset.hostname && asset.hostname !== asset.ip ? `${asset.hostname} · ` : ""}
          {ASSET_TYPE_LABEL[asset.asset_type] ?? asset.asset_type}
          {" · "}
          <span className={asset.status === "up" ? "is-up" : "is-down"}>{asset.status === "up" ? "en ligne" : "hors ligne"}</span>
        </>
      }
      onClose={() => ui.selectAsset(null)}
    >
      <div className="inspector-score">
        <div>
          <Score value={asset.risk_score} />
          <span className="unit">/100</span>
        </div>
        <RiskTag score={asset.risk_score} />
      </div>

      <AssetProfile asset={asset} label={label} />

      <h3 className="section-title">Pourquoi ce score</h3>
      <ul className="breakdown">
        {Object.entries(RISK_BREAKDOWN_MAX).map(([key, max]) => {
          const value = breakdown[key] ?? 0;
          return (
            <li key={key}>
              <span>{RISK_BREAKDOWN_LABEL[key]}</span>
              <Meter value={value} max={max} band={riskBand((value / max) * 100)} label={RISK_BREAKDOWN_LABEL[key]} />
              <span className="mono num">{value.toFixed(1)}</span>
            </li>
          );
        })}
      </ul>
      {asset.risk_factors?.factors && (
        <ul className="factors">
          {asset.risk_factors.factors.map((f, i) => (
            <li key={`${i}-${f}`}>{f}</li>
          ))}
        </ul>
      )}

      <h3 className="section-title">Exposition</h3>
      <dl className="facts">
        <dt>Ports ouverts</dt>
        <dd className="mono">{ports.length ? ports.join(" ") : "aucun détecté"}</dd>
        <dt>Services</dt>
        <dd>{services.length ? services.join(", ") : "—"}</dd>
        <dt>Système</dt>
        <dd>{asset.os_detected ?? "non identifié"}</dd>
        <dt>Constructeur</dt>
        <dd>{asset.vendor ?? "—"}</dd>
        <dt>MAC</dt>
        <dd className="mono">{asset.mac_address ?? "—"}</dd>
        <dt>Vu</dt>
        <dd>{formatRelative(asset.last_seen)}</dd>
      </dl>

      <h3 className="section-title">Relations</h3>
      {related.outgoing.length + related.incoming.length === 0 ? (
        <p className="muted">Aucune liaison active.</p>
      ) : (
        <ul className="relations">
          {related.outgoing.map((l) => (
            <li key={`o${l.target}`}>
              <span className="dir">vers</span>
              <button type="button" className="link-button mono" onClick={() => ui.selectAsset(l.target)}>{label(l.target)}</button>
              <span className="muted">{EVIDENCE_LABEL[l.evidence_level]}</span>
              <span className="mono num">{l.weight.toFixed(0)}</span>
            </li>
          ))}
          {related.incoming.map((l) => (
            <li key={`i${l.source}`}>
              <span className="dir">depuis</span>
              <button type="button" className="link-button mono" onClick={() => ui.selectAsset(l.source)}>{label(l.source)}</button>
              <span className="muted">{EVIDENCE_LABEL[l.evidence_level]}</span>
              <span className="mono num">{l.weight.toFixed(0)}</span>
            </li>
          ))}
        </ul>
      )}

      {(related.paths.length > 0 || related.incidents.length > 0) && (
        <p className="inspector-exposure">
          Présent dans {related.paths.length} chemin{related.paths.length > 1 ? "s" : ""} d'attaque
          {related.incidents.length > 0 && <> et {related.incidents.length} incident{related.incidents.length > 1 ? "s" : ""} actif{related.incidents.length > 1 ? "s" : ""}</>}.
        </p>
      )}

      {related.alerts.length > 0 && (
        <>
          <h3 className="section-title">Alertes récentes</h3>
          <ul className="mini-alerts">
            {related.alerts.map((a) => (
              <li key={a.id}>
                <PriorityTag priority={a.priority} />
                <span className="mini-alert-msg">{a.message}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}
