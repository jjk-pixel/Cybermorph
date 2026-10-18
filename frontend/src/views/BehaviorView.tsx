import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { Communication, Deviation } from "../api/types";
import { EmptyState, ErrorNote, Panel, Stat } from "../components/ui";
import {
  BASELINE_STATE_LABEL, DEVIATION_KIND_LABEL, formatBytes, formatCount, formatDateTime, formatRelative, SCOPE_LABEL,
  SEVERITY_LABEL, severityBand,
} from "../lib/format";
import { useAssetIndex } from "../lib/useAssets";
import { useResource } from "../lib/useResource";
import { requestRefresh, useLive } from "../state/live";
import { ui, useUi } from "../state/ui";

type StatusFilter = "open" | "acknowledged" | "learned" | "all";
type StateFilter = "all" | "baseline" | "new" | "accepted";

function service(c: Communication): string {
  const base = c.dst_port != null ? `${c.proto.toLowerCase()}/${c.dst_port}` : c.proto.toLowerCase();
  return c.app_proto ? `${base} · ${c.app_proto}` : base;
}

function DeviationRow({ deviation, label, onLearn, onAcknowledge, busy }: {
  deviation: Deviation; label: (id: number) => string; busy: boolean;
  onLearn: (d: Deviation) => void; onAcknowledge: (d: Deviation) => void;
}) {
  const highlight = useUi((s) => s.highlight);
  const nodes = [deviation.src_asset_id, deviation.dst_asset_id].filter((n): n is number => n != null);
  const active = nodes.length > 0 && highlight?.nodes.join(">") === nodes.join(">");
  const evidence = deviation.evidence;

  return (
    <li className={`deviation sev-${deviation.severity}${active ? " is-selected" : ""}`}>
      <div className="deviation-head">
        <span className={`tag tag-${severityBand(deviation.severity)}`}>{SEVERITY_LABEL[deviation.severity]}</span>
        <span className="deviation-kind">{DEVIATION_KIND_LABEL[deviation.kind] ?? deviation.kind}</span>
        <span className="muted small" title={formatDateTime(deviation.first_seen)}>
          {formatRelative(deviation.last_seen)}{deviation.occurrences > 1 ? ` · ×${formatCount(deviation.occurrences)}` : ""}
        </span>
      </div>
      <button
        type="button"
        className="deviation-text"
        disabled={nodes.length === 0}
        aria-pressed={active}
        onClick={() => ui.highlight(active ? null : { nodes })}
      >
        {deviation.explanation}
      </button>
      <ul className="deviation-reasons">
        {deviation.reasons.map((r) => <li key={r}>{r}</li>)}
      </ul>
      {(evidence.alert_ids?.length || evidence.flow_ids?.length || evidence.ports_sample?.length) ? (
        <p className="deviation-evidence mono">
          {evidence.alert_ids?.length ? `alertes #${evidence.alert_ids.join(", #")}  ` : ""}
          {evidence.flow_ids?.length ? `flow_id ${evidence.flow_ids.slice(-3).join(", ")}  ` : ""}
          {evidence.ports_sample?.length ? `ports ${evidence.ports_sample.slice(0, 12).join(" ")}${(evidence.distinct_ports ?? 0) > 12 ? " …" : ""}` : ""}
        </p>
      ) : null}
      <div className="deviation-actions">
        {nodes.map((id) => (
          <button key={id} type="button" className="link-button mono" onClick={() => ui.selectAsset(id)}>{label(id)}</button>
        ))}
        {deviation.status === "open" && deviation.kind === "new_communication" && (
          <button type="button" className="text-button" disabled={busy} onClick={() => onLearn(deviation)}>Apprendre</button>
        )}
        {deviation.status === "open" && (
          <button type="button" className="text-button" disabled={busy} onClick={() => onAcknowledge(deviation)}>Acquitter</button>
        )}
        {deviation.status !== "open" && (
          <span className="muted small">{deviation.status === "learned" ? "appris" : "acquitté"} {formatRelative(deviation.reviewed_at)}</span>
        )}
      </div>
    </li>
  );
}

/* Comportement : ce que le réseau fait d'habitude (référence) et ce qui s'en écarte, preuves à l'appui. */
export function BehaviorView() {
  const lastScan = useLive((s) => s.state?.last_scan_at);
  const openCount = useLive((s) => s.state?.stats.open_deviations ?? 0);
  const selectedId = useUi((s) => s.selectedAssetId);
  const [status, setStatus] = useState<StatusFilter>("open");
  const [state, setState] = useState<StateFilter>("all");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const { label } = useAssetIndex();

  const summary = useResource(() => api.behavior(), [lastScan, openCount]);
  const deviations = useResource(
    () => api.deviations({ status: status === "all" ? undefined : status, asset_id: selectedId ?? undefined }),
    [status, selectedId, lastScan, openCount],
  );
  const communications = useResource(
    () => api.communications({ state: state === "all" ? undefined : state, asset_id: selectedId ?? undefined }),
    [state, selectedId, lastScan],
  );

  useEffect(() => () => ui.highlight(null), []);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      deviations.reload();
      communications.reload();
      summary.reload();
      requestRefresh();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const data = summary.data;
  const run = data?.sensor.last_run;
  const commData = communications.data;
  const commList = useMemo(() => commData ?? [], [commData]);
  const totalFlows = useMemo(() => commList.reduce((n, c) => n + c.flow_count, 0), [commList]);
  const scope = selectedId != null ? ` de ${label(selectedId)}` : "";

  return (
    <div className="layout-split layout-behavior">
      <Panel
        className="panel-fill"
        title={`Écarts à la référence${scope}`}
        meta={data ? `${data.deviations.open} ouvert${data.deviations.open > 1 ? "s" : ""} · ${data.deviations.learned} appris · ${data.deviations.acknowledged} acquitté${data.deviations.acknowledged > 1 ? "s" : ""}` : "Chargement…"}
      >
        {data && (
          <p className={`learning-note${data.learning.in_learning ? " is-learning" : ""}`}>
            {data.learning.in_learning
              ? <>Apprentissage en cours jusqu'au <strong>{formatDateTime(data.learning.ends_at)}</strong> : les activités observées d'ici là forment la référence. Aucun écart « nouvelle activité » n'est émis pendant cette période ; les balayages et les hôtes hors inventaire sont signalés dès maintenant.</>
              : <>Référence apprise du {formatDateTime(data.learning.started_at)} au {formatDateTime(data.learning.ends_at)}. Un actif découvert ensuite apprend ses propres activités pendant {data.asset_learning_hours} h.</>}
          </p>
        )}
        {data && (
          <div className={`sensor-health${data.sensor.healthy ? "" : " is-down"}`}>
            <span className="sensor-dot" aria-hidden />
            {run && !run.error ? (
              <span>
                Suricata eve.json lu {formatRelative(run.at)} : {formatCount(Number(run.flows ?? 0))} flux,
                {" "}<strong>{formatCount(Number(run.probes_excluded ?? 0))}</strong> sondes du capteur écartées,
                {" "}{formatCount(Number(run.unanswered ?? 0))} tentatives TCP sans réponse.
              </span>
            ) : (
              <span>{run?.error ?? "Aucune lecture d'eve.json pour l'instant : elle a lieu à chaque cycle de collecte."}</span>
            )}
          </div>
        )}

        <div className="filters">
          <div className="segmented" role="group" aria-label="Statut des écarts">
            {([["open", "Ouverts"], ["acknowledged", "Acquittés"], ["learned", "Appris"], ["all", "Tous"]] as const).map(([v, t]) => (
              <button key={v} type="button" className={status === v ? "is-on" : ""} aria-pressed={status === v} onClick={() => setStatus(v)}>{t}</button>
            ))}
          </div>
        </div>
        {actionError && <ErrorNote message={actionError} />}
        {deviations.error && <ErrorNote message={deviations.error} onRetry={deviations.reload} />}
        {deviations.data && deviations.data.length === 0 && (
          <EmptyState title={status === "open" ? "Aucun écart ouvert" : "Aucun écart pour ce filtre"}>
            {data?.learning.in_learning
              ? "La référence est en cours d'apprentissage."
              : "Toutes les activités observées correspondent à la référence."}
          </EmptyState>
        )}
        <ul className="deviation-list">
          {(deviations.data ?? []).map((d) => (
            <DeviationRow
              key={d.id}
              deviation={d}
              label={label}
              busy={busy}
              onLearn={(x) => act(() => api.learnDeviation(x.id))}
              onAcknowledge={(x) => act(() => api.acknowledgeDeviation(x.id))}
            />
          ))}
        </ul>
      </Panel>

      <Panel
        className="panel-fill"
        title={`Activités observées${scope}`}
        meta={data ? `${data.communications.baseline} en référence · ${data.communications.new} nouvelles · ${data.communications.accepted} acceptées` : undefined}
      >
        {data && (
          <div className="stat-grid">
            <Stat label="Activités" value={commList.length} />
            <Stat label="Flux agrégés" value={formatCount(totalFlows)} />
            <Stat label="Hors référence" value={data.communications.new} tone={data.communications.new ? "moderate" : undefined} />
            <Stat label="Écarts ouverts" value={data.deviations.open} tone={data.deviations.open ? "high" : undefined} />
          </div>
        )}
        <div className="filters">
          <div className="segmented" role="group" aria-label="État dans la référence">
            {([["all", "Toutes"], ["baseline", "Référence"], ["new", "Nouvelles"], ["accepted", "Acceptées"]] as const).map(([v, t]) => (
              <button key={v} type="button" className={state === v ? "is-on" : ""} aria-pressed={state === v} onClick={() => setState(v)}>{t}</button>
            ))}
          </div>
        </div>
        {communications.error && <ErrorNote message={communications.error} onRetry={communications.reload} />}
        {communications.data && commList.length === 0 && (
          <EmptyState title="Aucune activité">Les flux Suricata sont lus à chaque cycle de collecte (5 min).</EmptyState>
        )}
        {commList.length > 0 && (
          <div className="table-wrap">
            <table className="table table-compact">
              <thead>
                <tr>
                  <th>Source → destination</th>
                  <th>Service</th>
                  <th className="num">Flux</th>
                  <th className="num">Volume</th>
                  <th>État</th>
                </tr>
              </thead>
              <tbody>
                {commList.map((c) => (
                  <tr key={c.id} className={c.baseline_state === "new" ? "band-moderate" : ""}>
                    <td>
                      <span className="mono cell-main">{c.src_ip} → {c.dst_scope === "local" ? c.dst_key : SCOPE_LABEL[c.dst_scope]}</span>
                      {(c.details.sni?.length || (c.dst_scope !== "local" && c.details.destinations?.length)) ? (
                        <span className="cell-sub" title={(c.details.destinations ?? []).join(", ")}>
                          {c.details.sni?.length ? c.details.sni.join(", ") : `${c.details.destinations?.length} destination(s)`}
                        </span>
                      ) : null}
                    </td>
                    <td className="mono">{service(c)}</td>
                    <td className="num mono">
                      {formatCount(c.flow_count)}
                      {c.proto === "TCP" && c.established_count < c.flow_count && <span className="cell-sub">{formatCount(c.established_count)} établis</span>}
                    </td>
                    <td className="num mono">{formatBytes(c.bytes_toserver + c.bytes_toclient)}</td>
                    <td>
                      <span className={`tag tag-baseline tag-baseline-${c.baseline_state}`}>{BASELINE_STATE_LABEL[c.baseline_state]}</span>
                      <span className="cell-sub">{formatRelative(c.last_seen)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && (
          <>
            <h3 className="section-title">Méthode</h3>
            <ul className="assumptions">
              {data.method.map((m) => <li key={m}>{m}</li>)}
            </ul>
          </>
        )}
      </Panel>
    </div>
  );
}
