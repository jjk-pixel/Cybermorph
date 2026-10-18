/*
 * État d'interface partagé entre les vues et la scène 3D : la scène est le fond
 * permanent de l'application et reflète ce que l'opérateur sélectionne ailleurs.
 */
import type { AttackPath, BlastRadius, IncidentStep, SnapshotDetail } from "../api/types";
import { createStore, useStore } from "./createStore";

export type ViewId = "overview" | "exposure" | "alerts" | "incidents" | "paths" | "mitre" | "timeline" | "simulations";

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
  /* rayon d'impact d'un actif supposé compromis (calcul sur le modèle) */
  blast: BlastRadius | null;
  /* liaison ou actif visé par une recommandation */
  highlight: { nodes: number[] } | null;
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
  blast: null,
  highlight: null,
  replay: null,
  planView: false,
  cameraResetKey: 0,
});

export const useUi = <S>(selector: (s: UiStore) => S) => useStore(uiStore, selector);

export const ui = {
  setView: (view: ViewId) => uiStore.set({ view, focusPath: null, focusIncident: null, highlight: null }),
  // Le rayon d'impact suit l'actif qui l'a demandé : changer de sélection l'efface
  selectAsset: (id: number | null) =>
    uiStore.set((s) => ({ selectedAssetId: id, blast: s.blast && s.blast.asset_id === id ? s.blast : null })),
  hoverAsset: (id: number | null) => uiStore.set({ hoveredAssetId: id }),
  focusPath: (path: AttackPath | null) => uiStore.set({ focusPath: path }),
  focusIncident: (focus: UiStore["focusIncident"]) => uiStore.set({ focusIncident: focus }),
  setSimulation: (simulation: SimulationOverlay | null) => uiStore.set({ simulation }),
  setReplay: (replay: SnapshotDetail | null) => uiStore.set({ replay }),
  setBlast: (blast: BlastRadius | null) => uiStore.set({ blast }),
  highlight: (highlight: UiStore["highlight"]) => uiStore.set({ highlight }),
  togglePlanView: () => uiStore.set((s) => ({ planView: !s.planView })),
  resetCamera: () => uiStore.set((s) => ({ cameraResetKey: s.cameraResetKey + 1 })),
};
