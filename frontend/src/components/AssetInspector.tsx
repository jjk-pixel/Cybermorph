import { useMemo } from "react";
import type { LiveLink } from "../api/types";
import {
  ASSET_TYPE_LABEL, EVIDENCE_LABEL, formatConfidence, formatRelative, FRESHNESS_LABEL, RELATION_CLASS_LABEL, splitList, STATUS_LABEL,
} from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useLive } from "../state/live";
import { ui, useUi } from "../state/ui";
import { AssetIdentity } from "./AssetIdentity";
import { AssetProfile } from "./AssetProfile";
import { AssetVulnerabilities } from "./AssetVulnerabilities";
import { RiskExplanation } from "./RiskExplanation";
import { Panel, PriorityTag, RiskTag, Score } from "./ui";

/* Provenance lisible d'une relation : chaque preuve avec son âge (une observation ancienne reste visible comme telle). */
function provenance(l: LiveLink): string {
  const parts: string[] = [];
  for (const d of l.details) {
    const when = d.last_seen ? formatRelative(d.last_seen) : "date inconnue";
    if (d.connection_type === "detected") {
      const service = d.protocol === "icmp" ? "icmp" : `${d.protocol}/${d.port}`;
      parts.push(`${service} observé ${d.source === "suricata_flow" ? "(flux)" : "(historique)"} ${when}`);
    } else if (d.connection_type === "neighbor_detected") {
      parts.push(`voisinage ARP ${when} (inférée : communication non démontrée)`);
    } else if (d.connection_type === "declared") {
      parts.push("déclarée");
    } else if (d.connection_type) {
      parts.push(d.connection_type);
    }
  }
  if (l.provenance?.ids) parts.push("alerte IDS");
  if (l.confidence != null) parts.push(`confiance ${formatConfidence(l.confidence)}`);
  return parts.join(" · ");
}

function relationClasses(l: LiveLink): string {
  return (l.relation_classes ?? []).map((c) => RELATION_CLASS_LABEL[c] ?? c).join(" + ") || EVIDENCE_LABEL[l.evidence_level];
}

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

  return (
    <Panel
      className="inspector"
      title={<span className="mono">{asset.ip}</span>}
      meta={
        <>
          {asset.hostname && asset.hostname !== asset.ip ? `${asset.hostname} · ` : ""}
          {ASSET_TYPE_LABEL[asset.asset_type] ?? asset.asset_type}
          {" · "}
          <span className={asset.status === "up" ? "is-up" : asset.status === "down" ? "is-down" : "is-unknown"}>{STATUS_LABEL[asset.status] ?? asset.status}</span>
          {asset.freshness && asset.freshness !== "fresh" && <span className="is-stale"> · {FRESHNESS_LABEL[asset.freshness]}</span>}
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
      <AssetIdentity asset={asset} />

      <h3 className="section-title">Pourquoi ce score</h3>
      <RiskExplanation asset={asset} />

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

      <AssetVulnerabilities assetId={asset.id} />

      <h3 className="section-title">Relations</h3>
      {related.outgoing.length + related.incoming.length === 0 ? (
        <p className="muted">Aucune liaison active.</p>
      ) : (
        <ul className="relations">
          {related.outgoing.map((l) => (
            <li key={`o${l.target}`}>
              <span className="dir">vers</span>
              <button type="button" className="link-button mono" onClick={() => ui.selectAsset(l.target)}>{label(l.target)}</button>
              <span className="muted" title={provenance(l)}>{relationClasses(l)}</span>
              <span className="mono num">{l.weight.toFixed(0)}</span>
              <span className="relation-provenance">{provenance(l)}</span>
            </li>
          ))}
          {related.incoming.map((l) => (
            <li key={`i${l.source}`}>
              <span className="dir">depuis</span>
              <button type="button" className="link-button mono" onClick={() => ui.selectAsset(l.source)}>{label(l.source)}</button>
              <span className="muted" title={provenance(l)}>{relationClasses(l)}</span>
              <span className="mono num">{l.weight.toFixed(0)}</span>
              <span className="relation-provenance">{provenance(l)}</span>
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
