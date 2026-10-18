import type { LiveAsset } from "../api/types";
import { formatConfidence, formatDateTime, RISK_BREAKDOWN_LABEL, RISK_BREAKDOWN_MAX, riskBand } from "../lib/format";
import { Meter } from "./ui";

/*
 * Pourquoi ce score : chaque critère avec ses points, les faits qui les justifient, les données manquantes et la
 * confiance. Les scores calculés avant le modèle 2 n'ont que la ventilation : elle est affichée telle quelle.
 */
export function RiskExplanation({ asset }: { asset: LiveAsset }) {
  const risk = asset.risk_factors;
  const contributors = risk?.contributors;

  if (!contributors) {
    const breakdown = risk?.breakdown ?? {};
    return (
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
    );
  }

  return (
    <div className="risk-explanation">
      <ul className="breakdown">
        {contributors.map((c) => (
          <li key={c.criterion} className="breakdown-criterion">
            <span>{c.label}</span>
            <Meter value={c.points} max={c.max} band={riskBand((c.points / c.max) * 100)} label={c.label} />
            <span className="mono num">{c.points.toFixed(1)}<span className="muted">/{c.max}</span></span>
            {(c.items.length > 0 || c.note) && (
              <ul className="breakdown-items">
                {c.items.map((i) => (
                  <li key={`${i.label}-${i.evidence.join(",")}`}>
                    <span className="breakdown-item-label">{i.label}</span>
                    <span className="mono num muted">{i.raw}</span>
                    {i.justification !== i.label && <span className="breakdown-why">{i.justification}</span>}
                  </li>
                ))}
                {c.note && <li className="breakdown-note">{c.note}</li>}
              </ul>
            )}
          </li>
        ))}
      </ul>

      {risk?.confidence && (
        <p className="small">
          Confiance du score <strong className="mono">{formatConfidence(risk.confidence.value)}</strong>
          <span className="muted"> : {risk.confidence.reasons.join(" ; ")}</span>
        </p>
      )}
      {risk?.missing_data && risk.missing_data.length > 0 && (
        <>
          <h4 className="subsection-title">Données manquantes</h4>
          <ul className="missing-list">
            {risk.missing_data.map((m) => <li key={m}>{m}</li>)}
          </ul>
        </>
      )}
      {risk?.compromise_indicators && risk.compromise_indicators.length > 0 && (
        <>
          <h4 className="subsection-title">Indices de compromission</h4>
          <ul className="missing-list">
            {risk.compromise_indicators.map((c) => <li key={`${c.incident_id}-${c.step}`}>{c.label}</li>)}
          </ul>
        </>
      )}
      <p className="muted small">
        {risk?.disclaimer} Risque potentiel{risk?.computed_at ? `, calculé le ${formatDateTime(risk.computed_at)}` : ""}.
      </p>
    </div>
  );
}
