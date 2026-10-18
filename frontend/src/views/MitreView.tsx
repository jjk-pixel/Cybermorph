import { useMemo, useState } from "react";
import { api } from "../api/client";
import type { ObservedTechnique, Technique } from "../api/types";
import { EmptyState, ErrorNote, Panel } from "../components/ui";
import { formatCount } from "../lib/format";
import { useResource } from "../lib/useResource";

/* Ordre canonique des tactiques ATT&CK Enterprise (de la reconnaissance à l'impact). */
const TACTICS: { name: string; label: string }[] = [
  { name: "Reconnaissance", label: "Reconnaissance" },
  { name: "Resource Development", label: "Préparation" },
  { name: "Initial Access", label: "Accès initial" },
  { name: "Execution", label: "Exécution" },
  { name: "Persistence", label: "Persistance" },
  { name: "Privilege Escalation", label: "Élévation" },
  { name: "Defense Evasion", label: "Évasion" },
  { name: "Credential Access", label: "Identifiants" },
  { name: "Discovery", label: "Découverte" },
  { name: "Lateral Movement", label: "Mouvement latéral" },
  { name: "Collection", label: "Collecte" },
  { name: "Command and Control", label: "Commande et contrôle" },
  { name: "Exfiltration", label: "Exfiltration" },
  { name: "Impact", label: "Impact" },
];

export function MitreView() {
  const catalog = useResource(() => api.techniques(), [], 300_000);
  const observed = useResource(() => api.observedTechniques(), [], 30_000);
  const [selected, setSelected] = useState<string | null>(null);

  const observedById = useMemo(
    () => new Map<string, ObservedTechnique>((observed.data ?? []).map((t) => [t.technique_id, t])),
    [observed.data],
  );

  const columns = useMemo(() => {
    const byTactic = new Map<string, Technique[]>();
    for (const t of catalog.data ?? []) byTactic.set(t.tactic, [...(byTactic.get(t.tactic) ?? []), t]);
    return TACTICS.map((tactic) => ({ ...tactic, techniques: byTactic.get(tactic.name) ?? [] }));
  }, [catalog.data]);

  const detail = selected ? observedById.get(selected) : undefined;
  const detailTechnique = catalog.data?.find((t) => t.technique_id === selected);
  const observedCount = observedById.size;

  return (
    <div className="layout-full">
      <Panel
        className="panel-fill"
        title="Couverture MITRE ATT&CK"
        meta={catalog.data ? `${observedCount} technique${observedCount > 1 ? "s" : ""} observée${observedCount > 1 ? "s" : ""} sur ${catalog.data.length} suivies` : "Chargement…"}
      >
        {(catalog.error || observed.error) && <ErrorNote message={(catalog.error ?? observed.error)!} onRetry={() => { catalog.reload(); observed.reload(); }} />}
        <div className="matrix" role="table" aria-label="Matrice des tactiques et techniques">
          {columns.map((column) => (
            <div key={column.name} className={`matrix-col${column.techniques.length ? "" : " is-uncovered"}`} role="rowgroup">
              <div className="matrix-head" role="columnheader" title={column.name}>{column.label}</div>
              {column.techniques.length === 0 ? (
                <div className="matrix-gap" role="cell">Non suivi</div>
              ) : (
                column.techniques.map((t) => {
                  const seen = observedById.get(t.technique_id);
                  const hits = seen?.alerts.reduce((sum, a) => sum + a.occurrence_count, 0) ?? 0;
                  return (
                    <button
                      key={t.technique_id}
                      type="button"
                      role="cell"
                      className={`matrix-cell${seen ? " is-observed" : ""}${selected === t.technique_id ? " is-selected" : ""}`}
                      aria-pressed={selected === t.technique_id}
                      onClick={() => setSelected(selected === t.technique_id ? null : t.technique_id)}
                    >
                      <span className="mono matrix-id">{t.technique_id}</span>
                      <span className="matrix-name">{t.name}</span>
                      {seen && <span className="mono matrix-hits">{formatCount(hits)} occ.</span>}
                    </button>
                  );
                })
              )}
            </div>
          ))}
        </div>

        {selected && detailTechnique && (
          <div className="matrix-detail">
            <h3 className="section-title">
              <span className="mono">{detailTechnique.technique_id}</span> {detailTechnique.name}
            </h3>
            <p className="muted">{detailTechnique.description}</p>
            {detail ? (
              <ul className="evidence-list">
                {detail.alerts.map((a) => (
                  <li key={a.alert_id}>
                    <span className="evidence-msg">{a.message}</span>
                    <span className="mono num">×{formatCount(a.occurrence_count)}</span>
                    <span className="mono num" title="Confiance du rapprochement alerte → technique">{Math.round(a.confidence * 100)} %</span>
                    {a.matched_on && <span className="evidence-reason">{a.matched_on}</span>}
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="Pas encore observée">Aucune alerte de ce lab n'a été rapprochée de cette technique.</EmptyState>
            )}
          </div>
        )}
        <p className="muted small">
          CYBERMORPH ne suit qu'un sous-ensemble d'ATT&CK, limité à ce que ses capteurs réseau peuvent réellement observer. Les colonnes « non suivi » sont hors de portée des capteurs actuels.
        </p>
      </Panel>
    </div>
  );
}
