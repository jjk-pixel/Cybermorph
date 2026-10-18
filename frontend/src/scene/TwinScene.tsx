import { useEffect, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { CameraControls, Grid } from "@react-three/drei";
import { Bloom, EffectComposer, Vignette } from "@react-three/postprocessing";
import { COLORS } from "../lib/format";
import { usePrefersReducedMotion } from "../lib/usePrefersReducedMotion";
import { ui, useUi } from "../state/ui";
import { AssetNode } from "./AssetNode";
import { RING_RADII, type Vec3 } from "./layout";
import { LinkArc } from "./LinkArc";
import { PathTrace } from "./PathTrace";
import { useSceneModel } from "./useSceneModel";

const HOME = { position: [0, 6.8, 11.5] as Vec3, target: [0, 1.1, 0] as Vec3 };
const PLAN = { position: [0, 17, 0.01] as Vec3, target: [0, 0, 0] as Vec3 };
const IDLE_BEFORE_ORBIT_MS = 8000;

function CameraRig({ positions, animate }: { positions: Map<number, Vec3>; animate: boolean }) {
  const controls = useRef<CameraControls>(null);
  const selectedId = useUi((s) => s.selectedAssetId);
  const planView = useUi((s) => s.planView);
  const resetKey = useUi((s) => s.cameraResetKey);
  const lastInteraction = useRef(0);

  const selected = selectedId != null ? positions.get(selectedId) : undefined;
  const [sx, sy, sz] = selected ?? [0, 0, 0];
  const hasSelection = selected !== undefined;

  useEffect(() => {
    const c = controls.current;
    if (!c) return;
    if (planView) {
      c.maxPolarAngle = 0.15;
      void c.setLookAt(...PLAN.position, ...PLAN.target, true);
      return;
    }
    c.maxPolarAngle = Math.PI * 0.47;
    if (hasSelection) {
      // Vol vers l'asset sélectionné, en gardant l'angle de vue horizontal actuel
      const azimuth = c.azimuthAngle;
      void c.setLookAt(sx + Math.sin(azimuth) * 5.5, sy + 3.2, sz + Math.cos(azimuth) * 5.5, sx, sy, sz, true);
    } else {
      void c.setLookAt(...HOME.position, ...HOME.target, true);
    }
  }, [planView, hasSelection, sx, sy, sz, resetKey]);

  useFrame((_, delta) => {
    const c = controls.current;
    if (!c || !animate || planView || hasSelection) return;
    if (performance.now() - lastInteraction.current < IDLE_BEFORE_ORBIT_MS) return;
    void c.rotate(delta * 0.035, 0, false);
  });

  return (
    <CameraControls
      ref={controls}
      makeDefault
      minDistance={3}
      maxDistance={24}
      smoothTime={0.6}
      onStart={() => { lastInteraction.current = performance.now(); }}
      onEnd={() => { lastInteraction.current = performance.now(); }}
    />
  );
}

function SceneContent({ animate }: { animate: boolean }) {
  const { assets, positions, links, linkIndex, traces, markers, emphasis } = useSceneModel();
  const selectedId = useUi((s) => s.selectedAssetId);
  const hoveredId = useUi((s) => s.hoveredAssetId);
  const focusing = emphasis.size > 0 && traces.some((t) => t.key === "focus" || t.kind === "simulated");

  return (
    <>
      <color attach="background" args={["#02060d"]} />
      <fog attach="fog" args={["#02060d", 14, 34]} />
      <ambientLight intensity={0.25} />
      <pointLight position={[0, 9, 0]} intensity={40} distance={30} color={COLORS.cyan} />
      <pointLight position={[-8, 3, 6]} intensity={18} distance={26} color={COLORS.blue} />
      <pointLight position={[8, 2, -6]} intensity={10} distance={24} color={COLORS.violet} />

      <Grid
        position={[0, 0, 0]}
        args={[40, 40]}
        cellSize={0.5}
        cellThickness={0.5}
        cellColor="#0b1d33"
        sectionSize={2.5}
        sectionThickness={0.9}
        sectionColor="#14366b"
        fadeDistance={30}
        fadeStrength={1.4}
        infiniteGrid
      />

      {/* Anneaux de rôle (serveurs, postes, périphérie) tracés au sol */}
      {RING_RADII.slice(1).map((radius) => (
        <mesh key={radius} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.005, 0]}>
          <ringGeometry args={[radius - 0.012, radius + 0.012, 128]} />
          <meshBasicMaterial color={COLORS.blue} transparent opacity={0.22} depthWrite={false} />
        </mesh>
      ))}

      {links.map((link) => (
        <LinkArc
          key={`${link.source}>${link.target}`}
          link={link}
          animate={animate}
          dimmed={focusing && !(emphasis.has(link.source) && emphasis.has(link.target))}
        />
      ))}

      {traces.map((trace) => (
        <PathTrace key={trace.key} trace={trace} positions={positions} linkIndex={linkIndex} animate={animate} />
      ))}

      {assets.map((asset) => {
        const position = positions.get(asset.id);
        if (!position) return null;
        return (
          <AssetNode
            key={asset.id}
            asset={asset}
            position={position}
            selected={asset.id === selectedId}
            hovered={asset.id === hoveredId}
            dimmed={focusing && !emphasis.has(asset.id) && asset.id !== selectedId}
            underAttack={markers.underAttack.has(asset.id)}
            compromised={markers.compromised === asset.id}
            exposed={markers.exposed === asset.id}
            animate={animate}
            onSelect={(id) => ui.selectAsset(id === selectedId ? null : id)}
            onHover={ui.hoverAsset}
          />
        );
      })}

      <CameraRig positions={positions} animate={animate} />

      <EffectComposer multisampling={0}>
        <Bloom mipmapBlur intensity={0.85} luminanceThreshold={0.22} luminanceSmoothing={0.3} />
        <Vignette eskil={false} offset={0.25} darkness={0.75} />
      </EffectComposer>
    </>
  );
}

export default function TwinScene() {
  const reducedMotion = usePrefersReducedMotion();

  return (
    <Canvas
      className="twin-canvas"
      dpr={[1, 2]}
      gl={{ antialias: true, powerPreference: "high-performance" }}
      camera={{ position: HOME.position, fov: 42, near: 0.1, far: 120 }}
      onPointerMissed={() => ui.selectAsset(null)}
      aria-label="Jumeau numérique 3D du réseau"
    >
      <SceneContent animate={!reducedMotion} />
    </Canvas>
  );
}
