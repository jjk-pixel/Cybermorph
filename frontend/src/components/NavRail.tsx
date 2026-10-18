import type { ComponentType, SVGProps } from "react";
import { useLive } from "../state/live";
import { ui, useUi, type ViewId } from "../state/ui";
import { BrandMark, IconAlert, IconExposure, IconIncident, IconMatrix, IconPath, IconSimulation, IconTimeline, IconTwin } from "./Icons";

const ITEMS: { id: ViewId; label: string; icon: ComponentType<SVGProps<SVGSVGElement>> }[] = [
  { id: "overview", label: "Jumeau", icon: IconTwin },
  { id: "exposure", label: "Exposition", icon: IconExposure },
  { id: "alerts", label: "Alertes", icon: IconAlert },
  { id: "incidents", label: "Incidents", icon: IconIncident },
  { id: "paths", label: "Chemins", icon: IconPath },
  { id: "mitre", label: "ATT&CK", icon: IconMatrix },
  { id: "timeline", label: "Historique", icon: IconTimeline },
  { id: "simulations", label: "Simulations", icon: IconSimulation },
];

export function NavRail() {
  const view = useUi((s) => s.view);
  const incidents = useLive((s) => s.state?.stats.active_incidents ?? 0);
  const alerts24h = useLive((s) => s.state?.stats.alerts_24h ?? 0);

  const badge = (id: ViewId) => (id === "incidents" ? incidents : id === "alerts" ? alerts24h : 0);

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
                  <span className={`rail-badge${id === "incidents" ? " is-hot" : ""}`} aria-label={`${count} en cours`}>
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
