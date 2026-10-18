import type { ComponentType, SVGProps } from "react";
import { useLive } from "../state/live";
import { ui, useUi, type ViewId } from "../state/ui";
import { BrandMark, IconAlert, IconBehavior, IconExposure, IconHealth, IconIncident, IconInventory, IconMatrix, IconPath, IconSimulation, IconTimeline, IconTwin } from "./Icons";

const ITEMS: { id: ViewId; label: string; icon: ComponentType<SVGProps<SVGSVGElement>> }[] = [
  { id: "overview", label: "Jumeau", icon: IconTwin },
  { id: "exposure", label: "Exposition", icon: IconExposure },
  { id: "inventory", label: "Inventaire", icon: IconInventory },
  { id: "behavior", label: "Comportement", icon: IconBehavior },
  { id: "alerts", label: "Alertes", icon: IconAlert },
  { id: "incidents", label: "Incidents", icon: IconIncident },
  { id: "paths", label: "Chemins", icon: IconPath },
  { id: "mitre", label: "ATT&CK", icon: IconMatrix },
  { id: "timeline", label: "Historique", icon: IconTimeline },
  { id: "simulations", label: "Simulations", icon: IconSimulation },
  { id: "health", label: "Supervision", icon: IconHealth },
];

export function NavRail() {
  const view = useUi((s) => s.view);
  const incidents = useLive((s) => s.state?.stats.active_incidents ?? 0);
  const alerts24h = useLive((s) => s.state?.stats.alerts_24h ?? 0);
  const unauthorized = useLive((s) => s.state?.stats.unauthorized_assets ?? 0);
  const deviations = useLive((s) => s.state?.stats.open_deviations ?? 0);
  const collection = useLive((s) => s.state?.collection);
  const collectionIssues = collection ? (collection.late ? 1 : 0) + collection.failing_steps.length : 0;

  const badge = (id: ViewId) =>
    id === "incidents" ? incidents : id === "alerts" ? alerts24h : id === "inventory" ? unauthorized : id === "behavior" ? deviations
      : id === "health" ? collectionIssues : 0;

  return (
    <nav className="rail" aria-label="Navigation principale">
      <div className="rail-brand" title="CYBERMORPH — jumeau numérique de sécurité">
        <BrandMark />
      </div>
      <ul className="rail-list">
        {ITEMS.map(({ id, label, icon: Icon }) => {
          const count = badge(id);
          return (
            <li key={id}>
              <button
                type="button"
                className={`rail-item${view === id ? " is-active" : ""}`}
                aria-current={view === id ? "page" : undefined}
                onClick={() => ui.setView(id)}
              >
                <Icon />
                <span className="rail-label">{label}</span>
                {count > 0 && (
                  <span className={`rail-badge${id === "incidents" || id === "inventory" || id === "health" ? " is-hot" : ""}`} aria-label={`${count} en cours`}>
                    {count > 99 ? "99+" : count}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
