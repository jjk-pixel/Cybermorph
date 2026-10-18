import { useMemo, useState } from "react";
import { api } from "../api/client";
import type { Correlation } from "../api/types";
import { EmptyState, ErrorNote, Panel, Stat } from "../components/ui";
import { CORRELATION_KIND_LABEL, formatConfidence, formatDateTime, formatRelative, FRESHNESS_LABEL, STATUS_LABEL } from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { ui } from "../state/ui";

const OVERALL_TEXT = { ok: "Collecte nominale", degraded: "Collecte dégradée", failing: "Collecte en défaut" } as const;
const OVERALL_TONE = { ok: "low", degraded: "moderate", failing: "critical" } as const;
const STEP_STATUS: Record<string, string> = {
  success: "réussie", partial: "partielle", failed: "en échec", interrupted: "interrompue", skipped: "sautée",
};

/* Supervision : ce que CYBERMORPH voit réellement, et depuis quand ; corrélations d'événements expliquées. */
export function HealthView() {
  const health = useResource(() => api.systemHealth(), [], 30_000);
  const correlations = useResource(() => api.correlations({ limit: 100 }), [], 60_000);
  const [openId, setOpenId] = useState<number | null>(null);
  const { label } = useAssetIndex();
  const h = health.data;

  return (
    <div className="layout-split">
      <Panel className="panel-fill" title="Santé de la collecte" meta={h ? h.refresh_note : "Chargement…"}>
        {health.error && <ErrorNote message={health.error} onRetry={health.reload} />}
        {h && (
          <>
            <div className="stat-grid">
              <Stat label="État" value={OVERALL_TEXT[h.status]} tone={OVERALL_TONE[h.status]} />
              <Stat label="Dernier cycle" value={h.cycle.last_cycle_at ? formatRelative(h.cycle.last_cycle_at) : "jamais"} tone={h.cycle.late ? "critical" : undefined} />
              <Stat label="Dernier scan Nmap" value={h.last_scan.status ? STEP_STATUS[h.last_scan.status] ?? h.last_scan.status : "—"} />
              <Stat label="Timer systemd" value={h.timer.available ? h.timer.active_state ?? "?" : "non lisible"} />
            </div>

            {h.issues.length > 0 && (
              <ul className="issue-list">
                {h.issues.map((i) => <li key={i.message} className={`issue issue-${i.severity}`}>{i.message}</li>)}
              </ul>
            )}

            <h3 className="section-title">Étapes du cycle</h3>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr><th scope="col">Étape</th><th scope="col">Dernier passage</th><th scope="col">Résultat</th><th scope="col">Dernier succès</th></tr>
                </thead>
                <tbody>
                  {h.steps.map((s) => (
                    <tr key={s.collector} className={s.last_status === "failed" || s.last_status === "interrupted" ? "band-high" : undefined}>
                      <td>{s.label}</td>
                      <td className="nowrap">{s.last_run_at ? formatRelative(s.last_run_at) : "jamais"}</td>
                      <td>
                        {s.last_status ? STEP_STATUS[s.last_status] ?? s.last_status : "—"}
                        {s.last_error && <div className="cell-sub">{s.last_error}</div>}
                      </td>
                      <td className="nowrap">{s.last_success_at ? formatDateTime(s.last_success_at) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="section-title">Fraîcheur par actif</h3>
            <ul className="freshness-list">
              {h.assets.map((a) => (
                <li key={a.asset_id}>
                  <button type="button" className="link-button mono" onClick={() => ui.selectAsset(a.asset_id)}>{a.ip}</button>
                  <span className={`freshness freshness-${a.freshness}`}>{FRESHNESS_LABEL[a.freshness]}</span>
                  <span className="muted small">{STATUS_LABEL[a.status] ?? a.status} · vu {formatRelative(a.last_seen)}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Panel>

      <Panel className="panel-fill" title="Corrélations" meta="Événements rapprochés, avec leurs sources et leur raisonnement">
        {correlations.error && <ErrorNote message={correlations.error} onRetry={correlations.reload} />}
        {correlations.data && correlations.data.length === 0 && (
          <EmptyState title="Aucune corrélation sur 24 h">
            Aucun ensemble d'événements liés n'a été repéré. Cela ne prouve pas l'absence d'activité : seuls les capteurs actifs sont pris en compte.
          </EmptyState>
        )}
        <ul className="correlation-list">
          {(correlations.data ?? []).map((c) => (
            <CorrelationRow key={c.id} correlation={c} open={openId === c.id} onToggle={() => setOpenId(openId === c.id ? null : c.id)} label={label} />
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function CorrelationRow({ correlation: c, open, onToggle, label }: { correlation: Correlation; open: boolean; onToggle: () => void; label: (id: number) => string }) {
  const counts = useMemo(() => {
    const by: Record<string, number> = {};
    for (const e of c.events) by[e.type] = (by[e.type] ?? 0) + 1;
    return by;
  }, [c.events]);
  return (
    <li className={`correlation${open ? " is-open" : ""}`}>
      <button type="button" className="correlation-head" aria-expanded={open} onClick={onToggle}>
        <span className="correlation-kind">{CORRELATION_KIND_LABEL[c.kind] ?? c.kind}</span>
        <span className="mono">{c.asset_id != null ? label(c.asset_id) : c.ip}</span>
        <span className="muted small">{c.event_count} événement{c.event_count > 1 ? "s" : ""} · confiance {formatConfidence(c.confidence)}</span>
        <span className="muted small">{formatDateTime(c.window_end)}</span>
      </button>
      {open && (
        <div className="correlation-body">
          <p className="small">{c.reasoning}</p>
          <p className="muted small">
            {c.relation_label} · {Object.entries(counts).map(([k, v]) => `${v} ${k === "alert" ? "alerte(s)" : k === "deviation" ? "écart(s)" : "changement(s)"}`).join(", ")}
            {c.techniques.length > 0 && <> · ATT&CK {c.techniques.join(", ")}</>}
          </p>
          <ol className="correlation-events">
            {c.events.map((e) => (
              <li key={`${e.type}${e.id}`}>
                <span className="mono small">{e.at ? formatDateTime(e.at) : "—"}</span>
                <span className="event-type">{e.type === "alert" ? `alerte #${e.id}` : e.type === "deviation" ? `écart #${e.id}` : `changement #${e.id}`}</span>
                <span className="small">{e.summary}</span>
              </li>
            ))}
          </ol>
          {c.asset_id != null && (
            <button type="button" className="text-button" onClick={() => ui.selectAsset(c.asset_id)}>Voir l'actif dans le jumeau</button>
          )}
        </div>
      )}
    </li>
  );
}
