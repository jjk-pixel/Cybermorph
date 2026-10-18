import { useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { BlastRadius, CriticalityLevel, LiveAsset } from "../api/types";
import { ASSET_TYPE_LABEL, CRITICALITY_LABEL, CRITICALITY_ORDER, formatConfidence } from "../lib/format";
import { requestRefresh } from "../state/live";
import { ui, useUi } from "../state/ui";
import { CriticalityTag } from "./CriticalityTag";
import { ErrorNote, Score } from "./ui";

const TYPES = ["router", "server", "pc", "iot", "unknown"];

/* Rôle, criticité et preuves de classification ; déclarations de l'opérateur. */
export function AssetProfile({ asset, label }: { asset: LiveAsset; label: (id: number) => string }) {
  const classification = asset.classification;
  const typeDeclared = asset.asset_type_source === "declared";

  return (
    <>
      <h3 className="section-title">Rôle et criticité</h3>
      <dl className="facts">
        <dt>Type</dt>
        <dd>
          {ASSET_TYPE_LABEL[asset.asset_type] ?? asset.asset_type}
          <span className="muted">
            {typeDeclared
              ? " · déclaré"
              : classification ? ` · inféré, confiance ${formatConfidence(classification.confidence)}` : " · inféré"}
          </span>
        </dd>
        <dt>Criticité</dt>
        <dd><CriticalityTag criticality={asset.criticality} /> <span className="muted">{asset.criticality.reasons.join(" ; ")}</span></dd>
      </dl>

      {classification && classification.reasons.length > 0 && (
        <ul className="evidence-reasons" aria-label="Preuves de classification">
          {classification.reasons.map((r, i) => (
            <li key={`${i}-${r.reason}`} className={r.supports ? "is-for" : "is-against"}>
              <span className="evidence-sign" aria-label={r.supports ? "appuie" : "contredit"}>{r.supports ? "+" : "−"}</span>
              <span>{r.reason}</span>
              <span className="muted small">{r.source}</span>
            </li>
          ))}
        </ul>
      )}
      {typeDeclared && classification && classification.type !== asset.asset_type && (
        <p className="muted small">Avis du classifieur : {ASSET_TYPE_LABEL[classification.type] ?? classification.type}.</p>
      )}

      <DeclarationForm key={asset.id} asset={asset} />
      <BlastRadiusBlock key={`b${asset.id}`} asset={asset} label={label} />
    </>
  );
}

function DeclarationForm({ asset }: { asset: LiveAsset }) {
  const declaredLevel = asset.criticality.source === "declared" ? asset.criticality.level : "";
  const [level, setLevel] = useState<string>(declaredLevel);
  const [reason, setReason] = useState(asset.criticality.source === "declared" ? asset.criticality.reasons[0] ?? "" : "");
  const [type, setType] = useState<string>(asset.asset_type_source === "declared" ? asset.asset_type : "");
  const [state, setState] = useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);

  const typeChanged = type !== (asset.asset_type_source === "declared" ? asset.asset_type : "");
  const levelChanged = level !== declaredLevel || (level !== "" && reason !== (asset.criticality.reasons[0] ?? ""));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState("saving");
    setError(null);
    try {
      await api.declareAsset(asset.id, {
        ...(levelChanged ? { criticality: (level || null) as CriticalityLevel | null, criticality_reason: level ? reason || null : null } : {}),
        ...(typeChanged ? { asset_type: type || null } : {}),
      });
      setState("saved");
      requestRefresh();
    } catch (e) {
      setError((e as Error).message);
      setState("idle");
    }
  };

  return (
    <form className="declare-form" onSubmit={submit}>
      <label className="field">
        <span>Criticité déclarée</span>
        <select className="input" value={level} onChange={(e) => { setLevel(e.target.value); setState("idle"); }}>
          <option value="">Aucune : utiliser l'inférence</option>
          {CRITICALITY_ORDER.map((l) => <option key={l} value={l}>{CRITICALITY_LABEL[l]}</option>)}
        </select>
      </label>
      {level && (
        <label className="field">
          <span>Justification</span>
          <input className="input" value={reason} maxLength={200} placeholder="Ex. : héberge les sauvegardes" onChange={(e) => { setReason(e.target.value); setState("idle"); }} />
        </label>
      )}
      <label className="field">
        <span>Type déclaré</span>
        <select className="input" value={type} onChange={(e) => { setType(e.target.value); setState("idle"); }}>
          <option value="">Aucun : utiliser la classification</option>
          {TYPES.map((t) => <option key={t} value={t}>{ASSET_TYPE_LABEL[t]}</option>)}
        </select>
      </label>
      <div className="declare-actions">
        <button type="submit" className="primary-button" disabled={state === "saving" || (!typeChanged && !levelChanged)}>
          {state === "saving" ? "Enregistrement…" : "Enregistrer la déclaration"}
        </button>
        {state === "saved" && <span className="muted small" role="status">Déclaration enregistrée, risque recalculé.</span>}
      </div>
      {error && <ErrorNote message={error} />}
    </form>
  );
}

function BlastRadiusBlock({ asset, label }: { asset: LiveAsset; label: (id: number) => string }) {
  const blast = useUi((s) => s.blast);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const shown: BlastRadius | null = blast?.asset_id === asset.id ? blast : null;

  const toggle = async () => {
    if (shown) {
      ui.setBlast(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      ui.setBlast(await api.blastRadius(asset.id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="blast">
      <button type="button" className={`text-button${shown ? " is-on" : ""}`} onClick={toggle} disabled={loading} aria-pressed={!!shown}>
        {loading ? "Calcul…" : shown ? "Masquer le rayon d'impact" : "Rayon d'impact si compromis"}
      </button>
      {error && <ErrorNote message={error} />}
      {shown && (
        <>
          <p className="small">
            {shown.reachable_count === 0
              ? "Aucun actif atteignable depuis celui-ci dans le modèle."
              : <>{shown.reachable_count} actif{shown.reachable_count > 1 ? "s" : ""} atteignable{shown.reachable_count > 1 ? "s" : ""}, dont <strong>{shown.critical_reachable} critique{shown.critical_reachable > 1 ? "s" : ""}</strong>. Tracé en violet pointillé.</>}
          </p>
          <ul className="blast-list">
            {shown.reachable.map((r) => (
              <li key={r.asset_id}>
                <button type="button" className="link-button mono" onClick={() => ui.selectAsset(r.asset_id)}>{label(r.asset_id)}</button>
                <span className="muted small">{r.hops} saut{r.hops > 1 ? "s" : ""}{r.critical ? " · critique" : ""}</span>
                <Score value={r.score} />
              </li>
            ))}
          </ul>
          <p className="muted small">{shown.hypothesis}</p>
        </>
      )}
    </div>
  );
}
