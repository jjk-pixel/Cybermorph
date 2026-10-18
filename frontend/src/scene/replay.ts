/*
 * Relecture d'un snapshot complet : ses relations enregistrées deviennent les liaisons de la scène.
 * Module pur (testé par node --test).
 */
import type { EvidenceLevel, LiveLink, SnapshotState } from "../api/types.ts";

/* Rang de solidité de la preuve, aligné sur EVIDENCE_RANK du backend (graph_engine). */
const EVIDENCE_RANK: Record<string, number> = { neighbor_detected: 1, inferred: 2, detected: 3, declared: 3 };
const EVIDENCE_LEVEL: Record<number, EvidenceLevel> = { 1: "voisinage_detecte", 2: "inferee", 3: "observee" };

export function linksFromSnapshot(relations: SnapshotState["relations"]): LiveLink[] {
  const byPair = new Map<string, LiveLink>();
  for (const r of relations) {
    const key = `${r.source}>${r.target}`;
    let link = byPair.get(key);
    if (!link) {
      link = {
        source: r.source, target: r.target, weight: 0, connection_types: [], evidence_level: "voisinage_detecte",
        details: [], alert_summary: null, provenance: { observed: false, inferred: false, declared: false, ids: false },
        observed_sources: [], last_seen: null,
      };
      byPair.set(key, link);
    }
    link.connection_types.push(r.connection_type);
    link.details.push({ protocol: r.protocol, port: r.port, connection_type: r.connection_type, source: r.origin, last_seen: r.last_seen });
    // Chaque liaison vaut sa preuve la plus forte
    const best = Math.max(...link.connection_types.map((t) => EVIDENCE_RANK[t] ?? 1));
    link.evidence_level = EVIDENCE_LEVEL[best];
    link.provenance.observed ||= r.connection_type === "detected";
    link.provenance.inferred ||= r.connection_type === "neighbor_detected" || r.connection_type === "inferred";
    link.provenance.declared ||= r.connection_type === "declared";
    if (r.connection_type === "detected") link.observed_sources = [...new Set([...link.observed_sources, r.origin ?? "historique"])];
    if (r.last_seen && (!link.last_seen || r.last_seen > link.last_seen)) link.last_seen = r.last_seen;
  }
  return [...byPair.values()];
}
