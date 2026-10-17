import {
  Grid,
  OrbitControls,
  PerspectiveCamera,
  Stars,
} from "@react-three/drei";

import {
  Canvas,
  useThree,
} from "@react-three/fiber";

import { useEffect, useMemo, useRef, useState } from "react";

import { NetworkNode } from "./NetworkNode";
import type { NetworkNodeData } from "./NetworkNode";

import { NetworkEdge } from "./NetworkEdge";

interface TopologyNode {
  id: number;
  name: string;
  ip: string;
  type: string;
  status: string;
}

interface TopologyEdge {
  source: number;
  target: number;
  protocol: string;
  port: number | null;
}

interface NetworkSceneProps {
  onSelectAsset: (asset: NetworkNodeData | null) => void;
  resetCameraKey: number;
}
function SceneContents({
  assets,
  nodes,
  edges,
  selectedId,
  onSelect,
  resetCameraKey,
}: {
  assets: NetworkNodeData[];
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selectedId: number | null;
  onSelect: (asset: NetworkNodeData) => void;
  resetCameraKey: number;
}) {
  const { camera } = useThree();

  const controlsRef = useRef<any>(null);

useEffect(() => {
  camera.position.set(0, 5.2, 9.5);

  if (controlsRef.current) {
    controlsRef.current.target.set(0, 1.45, 0);
    controlsRef.current.update();
  }
}, [camera, resetCameraKey]);

  /*
   * Positionnement circulaire des assets.
   * Tous les assets restent au-dessus de la grille.
   */
  const positions = useMemo(() => {
    const result = new Map<
      number,
      [number, number, number]
    >();

const radius = Math.min(
  3.6,
  Math.max(2.4, nodes.length * 0.55)
);

nodes.forEach((node, index) => {
  const angle =
    (index / Math.max(nodes.length, 1)) *
    Math.PI *
    2 -
    Math.PI / 2;

  const height =
    1.45 + (index % 2) * 0.3;

  result.set(node.id, [
    Math.cos(angle) * radius,
    height,
    Math.sin(angle) * radius,
  ]);
});
    return result;
  }, [nodes]);

  /*
   * Association ID topology -> données complètes asset.
   */
  const assetMap = useMemo(() => {
    return new Map(
      assets.map((asset) => [asset.id, asset])
    );
  }, [assets]);

  return (
    <>
      <PerspectiveCamera
        makeDefault
        position={[0, 5.2, 9.5]}
        fov={44}
      />

      <ambientLight intensity={0.35} />

      <pointLight
        position={[0, 5, 4]}
        intensity={25}
        distance={25}
      />

      <pointLight
        position={[-5, -2, -5]}
        intensity={12}
        distance={20}
      />

      <Stars
        radius={80}
        depth={30}
        count={900}
        factor={1.2}
        saturation={0}
        fade
        speed={0.15}
      />

      <Grid
        args={[30, 30]}
        cellSize={0.5}
        cellThickness={0.5}
        cellColor="#123143"
        sectionSize={5}
        sectionThickness={0.8}
        sectionColor="#17465e"
        fadeDistance={25}
        fadeStrength={1.2}
        infiniteGrid
      />

      {/* CONNEXIONS RÉELLES */}
      {edges.map((edge, index) => {
        const start = positions.get(edge.source);
        const end = positions.get(edge.target);

        if (!start || !end) {
          return null;
        }

        return (
          <NetworkEdge
            key={`${edge.source}-${edge.target}-${index}`}
            start={start}
            end={end}
          />
        );
      })}

      {/* ASSETS RÉELS */}
      {nodes.map((node) => {
        const position = positions.get(node.id);
        const asset = assetMap.get(node.id);

        if (!position || !asset) {
          return null;
        }

        return (
          <NetworkNode
            key={node.id}
            asset={asset}
            position={position}
            selected={selectedId === asset.id}
            onSelect={onSelect}
          />
        );
      })}

      <OrbitControls
	ref={controlsRef}
        enableDamping
        dampingFactor={0.08}
        minDistance={4}
        maxDistance={16}
        target={[0, 1.45, 0]}
	enablePan

	autoRotate
	autoRotateSpeed={0.35}
      />
    </>
  );
}

export function NetworkScene({
  onSelectAsset,
  resetCameraKey,
}: NetworkSceneProps) {

  const [assets, setAssets] =
    useState<NetworkNodeData[]>([]);

  const [nodes, setNodes] =
    useState<TopologyNode[]>([]);

  const [edges, setEdges] =
    useState<TopologyEdge[]>([]);

  const [selectedId, setSelectedId] =
    useState<number | null>(null);

  useEffect(() => {
    async function loadNetwork() {
      try {
        const [
          assetsResponse,
          topologyResponse,
        ] = await Promise.all([
          fetch("/api/assets/"),
          fetch("/api/connections/topology"),
        ]);

        if (!assetsResponse.ok) {
          throw new Error(
            `Assets API: ${assetsResponse.status}`
          );
        }

        if (!topologyResponse.ok) {
          throw new Error(
            `Topology API: ${topologyResponse.status}`
          );
        }

        const assetsData =
          await assetsResponse.json();

        const topologyData =
          await topologyResponse.json();

        const normalizedAssets: NetworkNodeData[] =
          assetsData.map((asset: any) => ({
            id: asset.id,
            name: asset.name,
            ip: asset.ip_address,
            type: asset.asset_type,
            status: asset.status,
            risk_score: asset.risk_score,
            hostname: asset.hostname,
            vendor: asset.vendor,
            os_detected: asset.os_detected,
            open_ports: asset.open_ports,
            services: asset.services,
          }));

        setAssets(normalizedAssets);
        setNodes(topologyData.nodes);
        setEdges(topologyData.edges);
      } catch (error) {
        console.error(
          "CYBERMORPH network loading error:",
          error
        );
      }
    }

    loadNetwork();
  }, []);

  function handleSelect(
    asset: NetworkNodeData
  ) {
    setSelectedId(asset.id);
    onSelectAsset(asset);
  }

  return (
    <Canvas
      dpr={[1, 2]}
      gl={{
        antialias: true,
        powerPreference: "high-performance",
      }}
      camera={{
        position: [0, 5.5, 9],
        fov: 45,
      }}
      onPointerMissed={() => {
        setSelectedId(null);
        onSelectAsset(null);
      }}
    >
      <color
        attach="background"
        args={["#030911"]}
      />

      <SceneContents
        assets={assets}
        nodes={nodes}
        edges={edges}
        selectedId={selectedId}
        onSelect={handleSelect}
	resetCameraKey={resetCameraKey}
      />
    </Canvas>
  );
}
