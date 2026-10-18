import type { AlertTrace } from "../api/types";
import { BASELINE_STATE_LABEL, DEVIATION_KIND_LABEL, formatCount, formatDateTime, formatRelative } from "../lib/format";
import { ui } from "../state/ui";
import { PriorityTag } from "./ui";

/*
 * Chaîne de preuves d'une alerte, de la ligne brute du capteur jusqu'aux conclusions qui l'utilisent.
 * Chaque lien affiche sa nature : un flow_id commun est un lien exact, une même paire d'IP un rapprochement.
 */
export function TraceChain({ trace, label }: { trace: AlertTrace; label: (id: number) => string }) {
  const { alert, sources } = trace;
  return (
    <ol className="trace">
      <li className="trace-step">
        <span className="trace-kind">Capteur</span>
        <div>
          <p className="small">
            <PriorityTag priority={alert.priority} /> {alert.message}
            <span className="muted"> · signature {alert.signature_id} · ×{formatCount(alert.occurrence_count)} du {formatDateTime(alert.first_seen)} au {formatDateTime(alert.last_seen)}</span>
          </p>
          {sources.note && <p className="muted small">{sources.note}</p>}
          {sources.fast_log_last && (
            <figure className="raw-line">
              <figcaption className="muted small">
                Dernière ligne {sources.fast_log_last.path} @ octet {formatCount(sources.fast_log_last.offset)}
              </figcaption>
              <pre className="mono">{sources.fast_log_last.line}</pre>
            </figure>
          )}
          {sources.eve_flow_ids.length > 0 && (
            <p className="mono small">
              eve.json flow_id {sources.eve_flow_ids.slice(-4).join(", ")}
              {sources.eve_last && <span className="muted"> · {sources.eve_last.proto} :{sources.eve_last.src_port} → :{sources.eve_last.dest_port}{sources.eve_last.app_proto ? ` (${sources.eve_last.app_proto})` : ""}</span>}
            </p>
          )}
        </div>
      </li>

      <li className="trace-step">
        <span className="trace-kind">Interprétation</span>
        <div className="small">
          {trace.mitre.length === 0
            ? <span className="muted">Aucune technique ATT&CK rattachée : aucune règle ne correspond assez clairement.</span>
            : trace.mitre.map((m) => (
              <p key={m.technique_id}>
                <span className="mono technique">{m.technique_id}</span> {m.name} <span className="muted">({m.tactic}, confiance {Math.round(m.confidence * 100)} %) — {m.matched_on}</span>
              </p>
            ))}
        </div>
      </li>

      <li className="trace-step">
        <span className="trace-kind">Activité</span>
        <div className="small">
          {trace.communications.length === 0
            ? <span className="muted">Aucune activité observée entre ces deux IP (sondes du capteur, ou flux antérieurs à l'ingestion).</span>
            : trace.communications.slice(0, 5).map((c) => (
              <p key={c.id}>
                <span className={`trace-link${c.link.startsWith("exact") ? " is-exact" : ""}`}>{c.link}</span>{" "}
                <span className="mono">{c.src_ip} → {c.dst_key} {c.proto.toLowerCase()}{c.dst_port != null ? `/${c.dst_port}` : ""}</span>
                <span className="muted"> · {BASELINE_STATE_LABEL[c.baseline_state]} · {formatCount(c.flow_count)} flux · vu {formatRelative(c.last_seen)}</span>
              </p>
            ))}
        </div>
      </li>

      <li className="trace-step">
        <span className="trace-kind">Conclusions</span>
        <div className="small">
          {trace.incidents.map((i) => (
            <p key={`i${i.id}`}><span className="trace-link">{i.link}</span> incident #{i.id} <span className="muted">({i.status}, confiance {Math.round(i.confidence * 100)} %)</span></p>
          ))}
          {trace.deviations.map((d) => (
            <p key={`d${d.id}`}><span className="trace-link">corrélé</span> {DEVIATION_KIND_LABEL[d.kind] ?? d.kind} : {d.explanation}</p>
          ))}
          {trace.attack_paths.slice(0, 4).map((p) => (
            <p key={p.nodes.join(">")}>
              <span className="trace-link">corrobore</span>{" "}
              <button type="button" className="link-button mono" onClick={() => ui.highlight({ nodes: p.nodes })}>
                {p.nodes.map(label).join(" → ")}
              </button>
              <span className="muted"> · chemin {p.score.toFixed(1)}</span>
            </p>
          ))}
          {trace.incidents.length + trace.deviations.length + trace.attack_paths.length === 0 && (
            <span className="muted">Aucune conclusion ne s'appuie sur cette alerte.</span>
          )}
        </div>
      </li>
    </ol>
  );
}
