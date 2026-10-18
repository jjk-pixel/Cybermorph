/*
 * État d'interface partagé entre les vues et la scène 3D : la scène est le fond
 * permanent de l'application et reflète ce que l'opérateur sélectionne ailleurs.
 */
import type { AttackPath, IncidentStep, SnapshotDetail } from "../api/types";
import { createStore, useStore } from "./createStore";

export type ViewId = "overview" | "alerts" | "incidents" | "paths" | "mitre" | "timeline" | "simulations";

export type SimulationOverlay = {
  name: string;
  compromisedAssetId: number | null;
  exposedAssetId: number | null;
  removedLink: [number, number] | null;
  newPaths: AttackPath[];
  escalatedPaths: AttackPath[];
};

type UiStore = {
  view: ViewId;
  selectedAssetId: number | null;
  hoveredAssetId: number | null;
  /* chemin mis en avant (liste des chemins, alerte, top chemin) */
  focusPath: AttackPath | null;
  /* trace d'incident mise en avant */
  focusIncident: { id: number; steps: IncidentStep[]; currentAssetId: number | null } | null;
  simulation: SimulationOverlay | null;
  /* relecture d'un snapshot historique dans la scène */
  replay: SnapshotDetail | null;
  planView: boolean;
  cameraResetKey: number;
};

export const uiStore = createStore<UiStore>({
  view: "overview",
  selectedAssetId: null,
  hoveredAssetId: null,
  focusPath: null,
  focusIncident: null,
  simulation: null,
  replay: null,
  planView: false,
  cameraResetKey: 0,
});

export const useUi = <S>(selector: (s: UiStore) => S) => useStore(uiStore, selector);

export const ui = {
  setView: (view: ViewId) => uiStore.set({ view, focusPath: null, focusIncident: null }),
  selectAsset: (id: number | null) => uiStore.set({ selectedAssetId: id }),
  hoverAsset: (id: number | null) => uiStore.set({ hoveredAssetId: id }),
  focusPath: (path: AttackPath | null) => uiStore.set({ focusPath: path }),
  focusIncident: (focus: UiStore["focusIncident"]) => uiStore.set({ focusIncident: focus }),
  setSimulation: (simulation: SimulationOverlay | null) => uiStore.set({ simulation }),
  setReplay: (replay: SnapshotDetail | null) => uiStore.set({ replay }),
  togglePlanView: () => uiStore.set((s) => ({ planView: !s.planView })),
  resetCamera: () => uiStore.set((s) => ({ cameraResetKey: s.cameraResetKey + 1 })),
};
