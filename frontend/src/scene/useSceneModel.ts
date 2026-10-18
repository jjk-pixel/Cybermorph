import { useMemo } from "react";
import type { AttackPath, LiveAsset, LiveIncident, LiveLink } from "../api/types";
import { useLive } from "../state/live";
import { useUi } from "../state/ui";
import { arcControl, computeLayout, linkSide, type Vec3 } from "./layout";

export type SceneLink = LiveLink & { from: Vec3; to: Vec3; mid: Vec3; removed: boolean };

export type Trace = {
  key: string;
  nodes: number[];
  kind: "predicted" | "simulated" | "incident-confirmed" | "incident-potential";
};

/* Dérive tout ce que la scène doit dessiner à partir de l'état live et de l'état d'interface. */
export function useSceneModel() {
  const live = useLive((s) => s.state);
  const view = useUi((s) => s.view);
  const focusPath = useUi((s) => s.focusPath);
  const focusIncident = useUi((s) => s.focusIncident);
  const simulation = useUi((s) => s.simulation);
  const replay = useUi((s) => s.replay);

  const liveAssets = live?.assets;
  const liveLinks = live?.links;
  const attackPaths = live?.attack_paths;
  const activeIncidents = live?.active_incidents;

  const assets: LiveAsset[] = useMemo(() => {
    const base = liveAssets ?? [];
    if (!replay) return base;
    // Relecture : on applique au réseau courant le risque et l'état du snapshot historique
    const past = new Map(replay.assets_summary.map((a) => [a.id, a]));
    return base
      .filter((a) => past.has(a.id))
      .map((a) => ({ ...a, risk_score: past.get(a.id)!.risk_score, status: past.get(a.id)!.status }));
  }, [liveAssets, replay]);

  const positions = useMemo(
    () => computeLayout(assets.map((a) => ({ id: a.id, ip: a.ip, asset_type: a.asset_type, risk_score: a.risk_score }))),
    [assets],
  );

  const links: SceneLink[] = useMemo(() => {
    const raw = liveLinks ?? [];
    const keys = new Set(raw.map((l) => `${l.source}>${l.target}`));
    const removed = simulation?.removedLink;
    return raw.flatMap((l) => {
      const from = positions.get(l.source);
      const to = positions.get(l.target);
      if (!from || !to) return [];
      const side = linkSide(keys.has(`${l.target}>${l.source}`));
      return [{
        ...l,
        from,
        to,
        mid: arcControl(from, to, side),
        removed: !!removed && removed[0] === l.source && removed[1] === l.target,
      }];
    });
  }, [liveLinks, positions, simulation?.removedLink]);

  const traces: Trace[] = useMemo(() => {
    const result: Trace[] = [];
    const pathTrace = (p: AttackPath, kind: Trace["kind"], key: string) => result.push({ key, nodes: p.nodes, kind });

    if (simulation) {
      simulation.newPaths.slice(0, 12).forEach((p, i) => pathTrace(p, "simulated", `sim-new-${i}`));
      simulation.escalatedPaths.slice(0, 12).forEach((p, i) => pathTrace(p, "simulated", `sim-esc-${i}`));
    }
    if (focusPath) {
      pathTrace(focusPath, "predicted", "focus");
    } else if (!simulation && !focusIncident && view === "overview" && attackPaths?.[0]) {
      // Par défaut, la vue d'ensemble montre le chemin d'attaque le plus probable
      pathTrace(attackPaths[0], "predicted", "top");
    }

    const incidents: { steps: LiveIncident["steps"]; id: number }[] = focusIncident
      ? [{ steps: focusIncident.steps, id: focusIncident.id }]
      : view === "overview"
        ? (activeIncidents ?? []).map((i) => ({ steps: i.steps, id: i.incident_id }))
        : [];
    for (const incident of incidents) {
      for (const step of incident.steps) {
        result.push({
          key: `inc-${incident.id}-${step.sequence}-${step.source_asset_id}-${step.destination_asset_id}`,
          nodes: [step.source_asset_id, step.destination_asset_id],
          kind: step.status === "confirmed" ? "incident-confirmed" : "incident-potential",
        });
      }
    }
    return result;
  }, [simulation, focusPath, focusIncident, view, attackPaths, activeIncidents]);

  const linkIndex = useMemo(() => new Map(links.map((l) => [`${l.source}>${l.target}`, l])), [links]);

  /* Marqueurs portés par les nœuds */
  const markers = useMemo(() => {
    const underAttack = new Set<number>();
    const incidentList = focusIncident
      ? [{ current_asset_id: focusIncident.currentAssetId }]
      : (activeIncidents ?? []);
    for (const i of incidentList) if (i.current_asset_id != null) underAttack.add(i.current_asset_id);
    return {
      underAttack,
      compromised: simulation?.compromisedAssetId ?? null,
      exposed: simulation?.exposedAssetId ?? null,
    };
  }, [activeIncidents, focusIncident, simulation]);

  const emphasis = useMemo(() => {
    const ids = new Set<number>();
    for (const t of traces) if (t.kind !== "incident-potential") t.nodes.forEach((n) => ids.add(n));
    return ids;
  }, [traces]);

  return { live, assets, positions, links, linkIndex, traces, markers, emphasis, replay };
}
