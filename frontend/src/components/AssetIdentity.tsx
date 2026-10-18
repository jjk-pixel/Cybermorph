import { useState } from "react";
import { api } from "../api/client";
import type { LiveAsset } from "../api/types";
import { formatConfidence, formatRelative } from "../lib/format";
import { useResource } from "../lib/useResource";
import { requestRefresh, useLive } from "../state/live";
import { AuthorizationTag, ChangeRow } from "./inventory";
import { ErrorNote } from "./ui";

const ATTRIBUTE_LABEL: Record<string, string> = { mac: "MAC", vendor: "Constructeur", os: "OS estimé", hostname: "Nom" };
const SOURCE_SHORT: Record<string, string> = {
  nmap: "Nmap", mdns: "mDNS", dns: "DNS", heuristic: "déduit", local: "local", arp: "ARP", dhcp: "DHCP", manual: "opérateur",
};

/* Identité rapprochée d'un actif : identifiants et sources, autorisation, drapeau scanner, derniers changements. */
export function AssetIdentity({ asset }: { asset: LiveAsset }) {
  const lastScan = useLive((s) => s.state?.last_scan_at);
  const detail = useResource(() => api.inventoryAsset(asset.id), [asset.id, lastScan, asset.authorization, asset.is_scanner]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const declare = async (body: Parameters<typeof api.declareAsset>[1]) => {
    setSaving(true);
    setError(null);
    try {
      await api.declareAsset(asset.id, body);
      requestRefresh();
      detail.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const identity = detail.data?.identity;

  return (
    <>
      <h3 className="section-title">Identité</h3>
      {detail.error && <ErrorNote message={detail.error} onRetry={detail.reload} />}
      {identity && (
        <>
          <p className="small" title={identity.reasons.join("\n")}>
            Confiance d'identité <strong className="mono">{formatConfidence(identity.confidence)}</strong>
            {identity.open_conflicts > 0 && <span className="tag tag-high"> {identity.open_conflicts} conflit{identity.open_conflicts > 1 ? "s" : ""}</span>}
          </p>
          {identity.identifiers.length === 0 ? (
            <p className="muted small">Aucun identifiant enregistré : le journal se remplit au prochain cycle de scan.</p>
          ) : (
            <ul className="identifiers">
              {identity.identifiers.map((i) => (
                <li key={`${i.attribute}-${i.value}`} className={i.current ? "" : "is-retired"}>
                  <span className="muted">{ATTRIBUTE_LABEL[i.attribute] ?? i.attribute}</span>
                  <span className={i.attribute === "mac" ? "mono" : ""}>{i.value}</span>
                  <span className="identifier-sources">
                    {[...new Set(i.sources)].map((s) => (
                      <span key={s} className={`source-chip${s === "heuristic" ? " is-inferred" : ""}`}>{SOURCE_SHORT[s] ?? s}</span>
                    ))}
                    {!i.current && <span className="muted small">ancien</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      <div className="identity-actions">
        <AuthorizationTag value={asset.authorization} />
        {asset.authorization !== "authorized" && (
          <button type="button" className="text-button" disabled={saving} onClick={() => declare({ authorization: "authorized" })}>Autoriser</button>
        )}
        {asset.authorization !== "unauthorized" && (
          <button type="button" className="text-button" disabled={saving} onClick={() => declare({ authorization: "unauthorized" })}>Marquer non autorisé</button>
        )}
        <label className="checkbox">
          <input type="checkbox" checked={asset.is_scanner} disabled={saving} onChange={(e) => declare({ is_scanner: e.target.checked })} />
          Scanner (ses sondes ne sont pas du trafic normal)
        </label>
      </div>
      {error && <ErrorNote message={error} />}

      {detail.data && detail.data.changes.length > 0 && (
        <>
          <h3 className="section-title">Derniers changements</h3>
          <ul className="change-list is-compact">
            {detail.data.changes.slice(0, 4).map((c) => <ChangeRow key={c.id} change={c} />)}
          </ul>
          <p className="muted small">Dernière observation {formatRelative(detail.data.observations[0]?.last_seen)}.</p>
        </>
      )}
    </>
  );
}
