import type { Criticality } from "../api/types";
import { CRITICALITY_LABEL, formatConfidence } from "../lib/format";

/* Criticité d'un actif : le trait plein signale une déclaration, le pointillé une inférence. */
export function CriticalityTag({ criticality }: { criticality: Criticality }) {
  const declared = criticality.source === "declared";
  const title = declared
    ? `Déclarée par l'opérateur : ${criticality.reasons.join(" ; ")}`
    : `Inférée (confiance ${formatConfidence(criticality.confidence)}) : ${criticality.reasons.join(" ; ")}`;
  return (
    <span className={`tag tag-crit tag-crit-${criticality.level}${declared ? " is-declared" : ""}`} title={title}>
      {CRITICALITY_LABEL[criticality.level] ?? criticality.level}
      <span className="visually-hidden">{declared ? " (déclarée)" : " (inférée)"}</span>
    </span>
  );
}
