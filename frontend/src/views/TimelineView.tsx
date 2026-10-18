import { useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { api } from "../api/client";
import type { SnapshotSummary } from "../api/types";
import { EmptyState, ErrorNote, Panel } from "../components/ui";
import { formatDateTime, formatTime, parseDate, riskBand } from "../lib/format";
import { useResource } from "../lib/useResource";
import { ui, useUi } from "../state/ui";

const W = 640;
const H = 120;
const PAD = { top: 10, right: 12, bottom: 22, left: 34 };

type Series = { title: string; unit: string; className: string; value: (s: SnapshotSummary) => number; max?: number };

const SERIES: Series[] = [
  { title: "Score du chemin le plus fort", unit: "/100", className: "series-score", value: (s) => s.highest_path_score ?? 0, max: 100 },
  { title: "Nombre de chemins d'attaque", unit: "", className: "series-count", value: (s) => s.attack_paths_count },
];

/* Petit graphique linéaire mono-série ; les deux graphiques partagent l'axe temporel et le curseur. */
function LineChart({
  series, points, hover, selected, onHover, onPick,
}: {
  series: Series;
  points: SnapshotSummary[];
  hover: number | null;
  selected: number | null;
  onHover: (i: number | null) => void;
  onPick: (i: number) => void;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const values = points.map(series.value);
  const max = series.max ?? Math.max(1, ...values);
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;
  const x = (i: number) => PAD.left + (points.length > 1 ? (i / (points.length - 1)) * innerW : innerW / 2);
  const y = (v: number) => PAD.top + innerH - (v / max) * innerH;
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const ticks = [0, max / 2, max];

  const indexAt = (event: MouseEvent<SVGSVGElement>) => {
    const rect = svg.current!.getBoundingClientRect();
    const px = ((event.clientX - rect.left) / rect.width) * W;
    const ratio = (px - PAD.left) / innerW;
    return Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1))));
  };

  const active = hover ?? selected;

  return (
    <figure className="chart">
      <figcaption className="chart-title">{series.title}</figcaption>
      <svg
        ref={svg}
        viewBox={`0 0 ${W} ${H}`}
        className={`chart-svg ${series.className}`}
        role="img"
        aria-label={`${series.title} sur ${points.length} scans`}
        onPointerMove={(e) => onHover(indexAt(e))}
        onPointerLeave={() => onHover(null)}
        onClick={(e) => onPick(indexAt(e))}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)} className="chart-grid" />
            <text x={PAD.left - 6} y={y(t) + 3.5} className="chart-tick" textAnchor="end">{Math.round(t)}</text>
          </g>
        ))}
        {points.length > 1 && [0, Math.floor((points.length - 1) / 2), points.length - 1].map((i) => (
          <text key={i} x={x(i)} y={H - 6} className="chart-tick" textAnchor={i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"}>
            {formatTime(points[i].captured_at)}
          </text>
        ))}
        <path d={d} className="chart-line" />
        {selected != null && <line x1={x(selected)} x2={x(selected)} y1={PAD.top} y2={PAD.top + innerH} className="chart-selected" />}
        {active != null && (
          <>
            <line x1={x(active)} x2={x(active)} y1={PAD.top} y2={PAD.top + innerH} className="chart-crosshair" />
            <circle cx={x(active)} cy={y(values[active])} r={4.5} className="chart-marker" />
          </>
        )}
      </svg>
      {active != null && (
        <div className="chart-tooltip" style={{ left: `${(x(active) / W) * 100}%` }}>
          <span className="mono">{values[active]}{series.unit}</span>
          <span>{formatDateTime(points[active].captured_at)}</span>
        </div>
      )}
    </figure>
  );
}

export function TimelineView() {
  const timeline = useResource(() => api.timeline(288), [], 60_000);
  const replay = useUi((s) => s.replay);
  const [hover, setHover] = useState<number | null>(null);
  const [loadingId, setLoadingId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Le backend renvoie du plus récent au plus ancien ; les graphiques se lisent de gauche (ancien) à droite
  const points = useMemo(
    () => [...(timeline.data ?? [])].sort((a, b) => (parseDate(a.captured_at)?.getTime() ?? 0) - (parseDate(b.captured_at)?.getTime() ?? 0)),
    [timeline.data],
  );
  const selected = replay ? points.findIndex((p) => p.id === replay.id) : -1;

  useEffect(() => () => ui.setReplay(null), []);

  const pick = async (index: number) => {
    const snapshot = points[index];
    if (!snapshot) return;
    setLoadingId(snapshot.id);
    setError(null);
    try {
      ui.setReplay(await api.snapshot(snapshot.id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="layout-split">
      <Panel
        className="panel-fill"
        title="Historique des scans"
        meta={points.length ? `${points.length} scans, du ${formatDateTime(points[0].captured_at)} au ${formatDateTime(points[points.length - 1].captured_at)}` : "Chargement…"}
      >
        {timeline.error && <ErrorNote message={timeline.error} onRetry={timeline.reload} />}
        {error && <ErrorNote message={error} />}
        {timeline.data && points.length === 0 && <EmptyState title="Aucun scan enregistré">Le premier snapshot est pris à la fin du prochain cycle (toutes les 5 min).</EmptyState>}
        {points.length > 0 && (
          <>
            {SERIES.map((s) => (
              <LineChart key={s.title} series={s} points={points} hover={hover} selected={selected >= 0 ? selected : null} onHover={setHover} onPick={pick} />
            ))}
            <p className="muted small">Cliquez sur un instant pour rejouer l'état du réseau dans la scène (risque et disponibilité de chaque actif).</p>

            {replay && (
              <div className="replay-summary">
                <h3 className="section-title">État au {formatDateTime(replay.captured_at)}</h3>
                <ul className="replay-assets">
                  {replay.assets_summary.map((a) => (
                    <li key={a.id}>
                      <span className={`asset-dot band-${a.status === "down" ? "down" : riskBand(a.risk_score)}`} aria-hidden />
                      <span className="mono">{a.ip}</span>
                      <span className="mono num">{(a.risk_score ?? 0).toFixed(1)}</span>
                    </li>
                  ))}
                </ul>
                {replay.alerts_summary.length > 0 && (
                  <ul className="mini-alerts">
                    {replay.alerts_summary.map((a, i) => (
                      <li key={`${i}-${a.message}`}><span className="mono">×{a.occurrence_count}</span> <span className="mini-alert-msg">{a.message}</span></li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            <h3 className="section-title">Scans récents</h3>
            <div className="table-wrap table-compact">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    <th scope="col" className="num">Actifs</th>
                    <th scope="col" className="num">Chemins</th>
                    <th scope="col" className="num">Score max</th>
                    <th scope="col"><span className="visually-hidden">Action</span></th>
                  </tr>
                </thead>
                <tbody>
                  {[...points].reverse().slice(0, 30).map((p) => (
                    <tr key={p.id} className={replay?.id === p.id ? "is-selected" : ""}>
                      <td className="nowrap">{formatDateTime(p.captured_at)}</td>
                      <td className="mono num">{p.assets_count}</td>
                      <td className="mono num">{p.attack_paths_count}</td>
                      <td className="mono num">{p.highest_path_score ?? "—"}</td>
                      <td>
                        <button type="button" className="text-button" onClick={() => pick(points.indexOf(p))} disabled={loadingId === p.id}>
                          {loadingId === p.id ? "Chargement…" : "Rejouer"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
