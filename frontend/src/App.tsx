import { lazy, Suspense, useEffect } from "react";
import { AssetInspector } from "./components/AssetInspector";
import { NavRail } from "./components/NavRail";
import { StatusBar } from "./components/StatusBar";
import { startLive, stopLive, useLive } from "./state/live";
import { useUi, type ViewId } from "./state/ui";
import { AlertsView } from "./views/AlertsView";
import { ExposureView } from "./views/ExposureView";
import { InventoryView } from "./views/InventoryView";
import { IncidentsView } from "./views/IncidentsView";
import { MitreView } from "./views/MitreView";
import { OverviewView } from "./views/OverviewView";
import { PathsView } from "./views/PathsView";
import { SimulationsView } from "./views/SimulationsView";
import { TimelineView } from "./views/TimelineView";

// La 3D (three.js, r3f, postprocessing) est chargée à part pour que l'interface s'affiche immédiatement
const TwinScene = lazy(() => import("./scene/TwinScene"));

const VIEWS: Record<ViewId, () => React.JSX.Element | null> = {
  overview: OverviewView,
  exposure: ExposureView,
  inventory: InventoryView,
  alerts: AlertsView,
  incidents: IncidentsView,
  paths: PathsView,
  mitre: MitreView,
  timeline: TimelineView,
  simulations: SimulationsView,
};

/* Vues qui occupent toute la largeur : la scène reste visible mais passe en retrait */
const FULL_VIEWS: ViewId[] = ["mitre"];

function BootScreen() {
  const status = useLive((s) => s.status);
  const error = useLive((s) => s.error);
  const offline = status === "offline";
  return (
    <div className="boot" role="status">
      <p className="boot-title">{offline ? "Le backend ne répond pas" : "Connexion au jumeau numérique…"}</p>
      {offline && (
        <div className="boot-help">
          <p>{error}</p>
          <p>Démarrez l'API depuis <span className="mono">backend/</span> :</p>
          <pre className="mono">../venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000</pre>
          <p className="muted">Nouvelle tentative automatique en cours.</p>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const view = useUi((s) => s.view);
  const hasState = useLive((s) => s.state !== null);
  const selected = useUi((s) => s.selectedAssetId);
  const View = VIEWS[view];
  const full = FULL_VIEWS.includes(view);

  useEffect(() => {
    startLive();
    return stopLive;
  }, []);

  return (
    <div className="app">
      <NavRail />
      <main className="stage">
        <div className={`scene-layer${full ? " is-receded" : ""}`}>
          <Suspense fallback={<div className="scene-fallback">Chargement de la scène 3D…</div>}>
            <TwinScene />
          </Suspense>
        </div>
        <StatusBar />
        {hasState ? (
          <div className={`view-layer view-${view}`}>
            <View />
            {selected != null && !full && (
              <div className="inspector-slot">
                <AssetInspector />
              </div>
            )}
          </div>
        ) : (
          <BootScreen />
        )}
      </main>
    </div>
  );
}
