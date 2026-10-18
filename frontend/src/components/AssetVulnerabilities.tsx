import { useState } from "react";
import { api } from "../api/client";
import type { VulnerabilityFinding } from "../api/types";
import { FINDING_STATUS_LABEL } from "../lib/format";
import { useResource } from "../lib/useResource";
import { requestRefresh } from "../state/live";
import { ErrorNote } from "./ui";

/* Correspondances CVE d'un actif et logiciels identifiés ; seules les correspondances confirmées comptent au risque. */
export function AssetVulnerabilities({ assetId }: { assetId: number }) {
  const findings = useResource(() => api.vulnerabilities({ asset_id: assetId }), [assetId], 60_000);
  const sources = useResource(() => api.vulnerabilitySources(), [], 300_000);
  const active = (findings.data ?? []).filter((f) => f.status !== "not_observed");

  return (
    <>
      <h3 className="section-title">Vulnérabilités</h3>
      {findings.error && <ErrorNote message={findings.error} onRetry={findings.reload} />}
      {sources.data && !sources.data.configured && (
        <p className="muted small">
          Aucune source de vulnérabilités configurée (flux NVD local ou API) : les CVE ne sont pas évaluées.
          Ce n'est pas une absence de vulnérabilité.
        </p>
      )}
      {sources.data?.configured && findings.data && active.length === 0 && (
        <p className="muted small">Aucune correspondance pour les logiciels identifiés de cet actif.</p>
      )}
      {active.length > 0 && (
        <ul className="finding-list">
          {active.map((f) => <FindingRow key={f.id} finding={f} onDecided={findings.reload} />)}
        </ul>
      )}
    </>
  );
}

function FindingRow({ finding, onDecided }: { finding: VulnerabilityFinding; onDecided: () => void }) {
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const pending = finding.status === "probable" || finding.status === "uncertain";

  const decide = async (status: "confirmed" | "rejected") => {
    setSaving(true);
    setError(null);
    try {
      await api.decideFinding(finding.id, status, note);
      onDecided();
      requestRefresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <li className={`finding finding-${finding.status}`}>
      <div className="finding-head">
        <span className="mono">{finding.cve_id}</span>
        <span className="finding-status">{FINDING_STATUS_LABEL[finding.status] ?? finding.status}</span>
        <span className="mono num">{finding.cvss_score != null ? `CVSS ${finding.cvss_score}` : "CVSS inconnu"}</span>
      </div>
      <div className="muted small">
        {[finding.product, finding.version].filter(Boolean).join(" ") || "Logiciel"}{finding.port ? ` · port ${finding.port}` : ""} · {finding.status_reason}
      </div>
      {pending && (
        <div className="finding-decide">
          <input className="input" value={note} maxLength={500} placeholder="Vérification effectuée (obligatoire)"
                 aria-label={`Motif de la décision sur ${finding.cve_id}`} onChange={(e) => setNote(e.target.value)} />
          <button type="button" className="text-button" disabled={saving || note.trim().length < 3} onClick={() => decide("confirmed")}>Confirmer</button>
          <button type="button" className="text-button" disabled={saving || note.trim().length < 3} onClick={() => decide("rejected")}>Rejeter</button>
        </div>
      )}
      {finding.validated_note && <div className="muted small">Décision : {finding.validated_note}</div>}
      {error && <ErrorNote message={error} />}
    </li>
  );
}
