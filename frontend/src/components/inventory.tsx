import type { AssetChange, InventoryEntry } from "../api/types";
import { AUTHORIZATION_LABEL, CHANGE_TYPE_LABEL, formatDateTime, formatRelative, SEVERITY_LABEL, severityBand } from "../lib/format";
import { ui } from "../state/ui";

export function AuthorizationTag({ value }: { value: InventoryEntry["authorization"] }) {
  if (!value) return <span className="tag tag-auth">À statuer</span>;
  return <span className={`tag tag-auth tag-auth-${value}`}>{AUTHORIZATION_LABEL[value]}</span>;
}

export function ChangeRow({ change, label, onAcknowledge }: {
  change: AssetChange; label?: (id: number) => string; onAcknowledge?: (c: AssetChange) => void;
}) {
  return (
    <li className={`change-row sev-${change.severity}${change.acknowledged_at ? " is-acknowledged" : ""}`}>
      <span className="mono change-time" title={formatDateTime(change.detected_at)}>{formatRelative(change.detected_at)}</span>
      <span className={`tag tag-${severityBand(change.severity)}`}>{SEVERITY_LABEL[change.severity]}</span>
      <span className="change-type">{CHANGE_TYPE_LABEL[change.change_type] ?? change.change_type}</span>
      {label && change.asset_id != null && (
        <button type="button" className="link-button mono" onClick={() => ui.selectAsset(change.asset_id)}>{label(change.asset_id)}</button>
      )}
      <span className="change-text">{change.explanation}</span>
      {onAcknowledge && !change.acknowledged_at && (
        <button type="button" className="text-button change-ack" onClick={() => onAcknowledge(change)}>Acquitter</button>
      )}
      {change.acknowledged_at && <span className="muted small change-ack">acquitté</span>}
    </li>
  );
}
