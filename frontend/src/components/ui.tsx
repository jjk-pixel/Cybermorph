import type { ReactNode } from "react";
import type { AttackPath } from "../api/types";
import { EVIDENCE_LABEL, RISK_LABEL, priorityBand, riskBand, type RiskBand } from "../lib/format";
import { IconClose } from "./Icons";

export function Panel({
  title, meta, actions, children, className = "", onClose,
}: { title?: ReactNode; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; onClose?: () => void }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions || onClose) && (
        <header className="panel-head">
          <div className="panel-heading">
            {title && <h2 className="panel-title">{title}</h2>}
            {meta && <div className="panel-meta">{meta}</div>}
          </div>
          <div className="panel-actions">
            {actions}
            {onClose && (
              <button type="button" className="icon-button" onClick={onClose} aria-label="Fermer">
                <IconClose />
              </button>
            )}
          </div>
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function RiskTag({ score, band }: { score?: number | null; band?: RiskBand }) {
  const b = band ?? riskBand(score);
  return <span className={`tag tag-${b}`}>{RISK_LABEL[b]}</span>;
}

export function PriorityTag({ priority }: { priority: number | null | undefined }) {
  return (
    <span className={`tag tag-${priorityBand(priority)}`} title="Priorité Suricata (1 = la plus sévère)">
      P{priority ?? "?"}
    </span>
  );
}

export function EvidenceTag({ level }: { level: string }) {
  return <span className={`tag tag-evidence tag-evidence-${level}`}>{EVIDENCE_LABEL[level] ?? level}</span>;
}

export function Score({ value, band }: { value: number | null | undefined; band?: RiskBand }) {
  const v = Number(value ?? 0);
  return <span className={`score score-${band ?? riskBand(v)}`}>{v.toFixed(1)}</span>;
}

/* Barre horizontale 0 → max, utilisée pour les scores et les critères de risque. */
export function Meter({ value, max = 100, band, label }: { value: number; max?: number; band?: RiskBand; label?: string }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="meter" role="meter" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={label}>
      <div className={`meter-fill meter-${band ?? riskBand(pct)}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Hops({ path, label }: { path: AttackPath; label: (id: number) => string }) {
  return (
    <ol className="hops" aria-label="Sauts du chemin">
      {path.nodes.map((id, i) => (
        <li key={`${id}-${i}`} className="hop">
          <span className="mono">{label(id)}</span>
        </li>
      ))}
    </ol>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-text">{children}</div>}
    </div>
  );
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error-note" role="alert">
      <span>{message}</span>
      {onRetry && (
        <button type="button" className="text-button" onClick={onRetry}>
          Réessayer
        </button>
      )}
    </div>
  );
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: RiskBand | "violet" | "cyan" }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}
