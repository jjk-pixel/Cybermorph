import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Line, Text, Grid } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import { useMemo, useRef, useState } from "react";
import * as THREE from "three";
import type { Asset, Edge, AttackPath, ActiveIncident } from "../hooks/useLiveState";
function riskColor(score: number): string {
  if (score >= 75) return "#ff4444";
  if (score >= 50) return "#ff8c3d";
  if (score >= 25) return "#ffc23d";
  return "#3dffa0";
}

function assetSize(type: string): number {
  if (type === "router") return 0.55;
  if (type === "server") return 0.45;
  return 0.32;
}

function layoutPositions(assets: Asset[]): Record<number, [number, number, number]> {
  const positions: Record<number, [number, number, number]> = {};
  const radius = 4.5;
  assets.forEach((a, i) => {
    const angle = (i / assets.length) * Math.PI * 2;
    positions[a.id] = [Math.cos(angle) * radius, 0, Math.sin(angle) * radius];
  });
  return positions;
}

function getStepStatus(
  incidents: ActiveIncident[], source: number, target: number
): "confirmed" | "potential" | null {
  for (const incident of incidents) {
    const step = incident.steps.find(
      (s) => s.source_asset_id === source && s.destination_asset_id === target
    );
    if (step?.status === "confirmed") return "confirmed";
    if (step?.status === "potential") return "potential";
  }
  return null;
}

function AssetNode({
  asset, position, isSelected, isCompromised, onSelect,
}: {
  asset: Asset;
  position: [number, number, number];
  isSelected: boolean;
  isCompromised?: boolean;
  onSelect: () => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const haloRef = useRef<THREE.Mesh>(null);
  const size = assetSize(asset.asset_type);
  const color = riskColor(asset.risk_score);
  const isCritical = asset.risk_score >= 50 || isCompromised;
  const displayColor = isCompromised ? "#B57BFF" : color;

  useFrame(({ clock }) => {
    if (isCritical && haloRef.current) {
      const t = clock.getElapsedTime();
      const pulse = 1 + Math.sin(t * 2.5) * 0.15;
      haloRef.current.scale.setScalar(pulse);
      const mat = haloRef.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.25 + Math.sin(t * 2.5) * 0.15;
    }
  });

  return (
    <group position={position}>
      {isCritical && (
        <mesh ref={haloRef}>
          <sphereGeometry args={[size * 1.6, 24, 24]} />
          <meshBasicMaterial color={displayColor} transparent opacity={0.25} depthWrite={false} />
        </mesh>
      )}
      <mesh ref={meshRef} onClick={onSelect}>
        <sphereGeometry args={[size, 32, 32]} />
        <meshStandardMaterial
          color={displayColor}
          emissive={displayColor}
          emissiveIntensity={isSelected || isCompromised ? 1.4 : 0.7}
          toneMapped={false}
        />
      </mesh>
      <Text position={[0, size + 0.35, 0]} fontSize={0.22} color="#D7DEE8" anchorX="center">
        {asset.hostname || asset.ip}
      </Text>
    </group>
  );
}

function EdgeLine({
  from, to, color, lineWidth, dashed, opacity, animated,
}: {
  from: [number, number, number]; to: [number, number, number];
  color: string; lineWidth: number; dashed: boolean; opacity: number; animated: boolean;
}) {
  const lineRef = useRef<any>(null);

  useFrame(({ clock }) => {
    if (animated && lineRef.current?.material) {
      lineRef.current.material.dashOffset = -clock.getElapsedTime() * 1.5;
    }
  });

  return (
    <Line
      ref={lineRef}
      points={[from, to]}
      color={color}
      lineWidth={lineWidth}
      dashed={dashed || animated}
      dashSize={animated ? 0.3 : 0.15}
      gapSize={animated ? 0.15 : 0.1}
      transparent
      opacity={opacity}
    />
  );
}

interface Props {
  assets: Asset[];
  edges: Edge[];
  attackPaths: AttackPath[];
  activeIncidents: ActiveIncident[];
  onSelect: (asset: Asset) => void;
  selectedId?: number;
  simulatedPaths?: { source: number; target: number; nodes: number[] }[];
  compromisedAssetId?: number | null;
}

export default function NetworkGraph({
  assets, edges, attackPaths, activeIncidents, onSelect, selectedId, simulatedPaths, compromisedAssetId,
}: Props) {
  const positions = useMemo(() => layoutPositions(assets), [assets.map((a) => a.id).join(",")]);
  const highRiskPairs = new Set(
    attackPaths.filter((p) => p.score >= 50).map((p) => `${p.source}-${p.target}`)
  );
  const controlsRef = useRef<any>(null);

  return (
    <Canvas camera={{ position: [0, 6, 11], fov: 50 }} gl={{ antialias: true }}>
      <color attach="background" args={["#060910"]} />
      <fog attach="fog" args={["#060910", 12, 26]} />
      <ambientLight intensity={0.35} />
      <pointLight position={[8, 10, 8]} intensity={1} color="#8fb4ff" />
      <pointLight position={[-8, -4, -8]} intensity={0.4} color="#ff6a3d" />

      <Grid
        args={[40, 40]}
        cellColor="#1b2436"
        sectionColor="#28344a"
        cellSize={1}
        sectionSize={5}
        fadeDistance={22}
        fadeStrength={1.5}
        position={[0, -1.2, 0]}
      />

      {edges.map((e, i) => {
        const from = positions[e.source];
        const to = positions[e.target];
        if (!from || !to) return null;

        const incidentStatus = getStepStatus(activeIncidents, e.source, e.target);
        const isRiskPath = highRiskPairs.has(`${e.source}-${e.target}`);

        let color = "#3A4358";
        let lineWidth = 1;
        let dashed = e.connection_type === "neighbor_detected";
        let opacity = 0.6;

        if (incidentStatus === "confirmed") {
          color = "#ff2222"; lineWidth = 3; dashed = false; opacity = 1;
        } else if (incidentStatus === "potential") {
          color = "#ff8c3d"; lineWidth = 2; dashed = true; opacity = 0.85;
        } else if (isRiskPath) {
          color = "#ff4444"; lineWidth = 2.5; opacity = 1;
        }

        return (
          <EdgeLine
            key={i}
            from={from}
            to={to}
            color={color}
            lineWidth={lineWidth}
            dashed={dashed}
            opacity={opacity}
            animated={incidentStatus === "confirmed" || isRiskPath}
          />
        );
      })}

      {simulatedPaths?.map((p, pi) =>
        p.nodes.slice(0, -1).map((nodeId, i) => {
          const from = positions[nodeId];
          const to = positions[p.nodes[i + 1]];
          if (!from || !to) return null;
          return (
            <Line
              key={`sim-${pi}-${i}`}
              points={[from, to]}
              color="#B57BFF"
              lineWidth={2.5}
              dashed
              dashSize={0.25}
              gapSize={0.12}
              transparent
              opacity={0.9}
            />
          );
        })
      )}

      {assets.map((asset) => {
        const pos = positions[asset.id];
        if (!pos) return null;
        return (
          <AssetNode
            key={asset.id}
            asset={asset}
            position={pos}
            isSelected={asset.id === selectedId}
            isCompromised={asset.id === compromisedAssetId}
            onSelect={() => onSelect(asset)}
          />
        );
      })}

      <OrbitControls
        ref={controlsRef}
        enablePan={false}
        minDistance={4}
        maxDistance={22}
        autoRotate={!selectedId}
        autoRotateSpeed={0.6}
        enableDamping
        dampingFactor={0.08}
      />

      <EffectComposer>
        <Bloom intensity={0.9} luminanceThreshold={0.15} luminanceSmoothing={0.4} mipmapBlur />
      </EffectComposer>
    </Canvas>
  );
}
