import { useMemo } from "react";
import { Html } from "@react-three/drei";
import type { ThreeEvent } from "@react-three/fiber";

export type NetworkNodeData = {
  id: number;
  name?: string;
  ip: string;
  hostname?: string | null;
  type?: string;
  status?: string;
  risk_score?: number;
  vendor?: string | null;
  os_detected?: string | null;
  open_ports?: string;
  services?: string;
};

type NetworkNodeProps = {
  asset: NetworkNodeData;
  position?: [number, number, number];
  selected?: boolean;
  onSelect?: (asset: NetworkNodeData) => void;
  onSelectAsset?: (asset: NetworkNodeData | null) => void;
};

export function NetworkNode({
  asset,
  position = [0, 1.2, 0],
  selected = false,
  onSelect,
  onSelectAsset,
}: NetworkNodeProps) {
  /*
   * Couleur basée sur le risque réel de l'asset.
   */
  const color = useMemo(() => {
    const risk = Number(asset.risk_score ?? 0);

    if (asset.status === "down") {
      return "#4b5563";
    }

    if (risk >= 75) {
      return "#ff1744";
    }

    if (risk >= 50) {
      return "#ff8c00";
    }

    if (risk >= 25) {
      return "#ffd600";
    }

    return "#00e5ff";
  }, [asset.risk_score, asset.status]);

  /*
   * Un asset sélectionné est légèrement plus visible.
   */
  const radius = selected ? 0.38 : 0.32;

  const handleSelect = (event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation();

    onSelect?.(asset);
    onSelectAsset?.(asset);
  };

  return (
    <group position={position}>
      {/* HALO */}
      <mesh
        position={[0, 0, 0]}
        onPointerDown={handleSelect}
      >
        <sphereGeometry args={[radius * 1.55, 32, 32]} />

        <meshBasicMaterial
          color={color}
          transparent
          opacity={selected ? 0.16 : 0.08}
          depthWrite={false}
        />
      </mesh>

      {/* NŒUD PRINCIPAL */}
      <mesh
        position={[0, 0, 0]}
        onPointerDown={handleSelect}
      >
        <sphereGeometry args={[radius, 32, 32]} />

        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={selected ? 0.7 : 0.35}
          roughness={0.28}
          metalness={0.55}
        />
      </mesh>

      {/* POINT CENTRAL */}
      <mesh
        position={[0, 0, 0]}
        onPointerDown={handleSelect}
      >
        <sphereGeometry
          args={[radius * 0.45, 20, 20]}
        />

        <meshBasicMaterial color="#ffffff" />
      </mesh>

      {/* IP AU-DESSUS */}
      <Html
        position={[0, radius + 0.42, 0]}
        center
        distanceFactor={8}
        zIndexRange={[10, 0]}
        style={{
          pointerEvents: "none",
          userSelect: "none",
        }}
      >
        <div
          style={{
            color: "#e5faff",
            background: "rgba(2, 8, 16, 0.88)",
            border: `1px solid ${color}`,
            borderRadius: "4px",
            padding: "4px 8px",
            fontFamily:
              "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: "11px",
            fontWeight: 600,
            letterSpacing: "0.04em",
            whiteSpace: "nowrap",
            boxShadow: `0 0 12px ${color}55`,
          }}
        >
          {asset.ip}
        </div>
      </Html>

      {/* TYPE */}
      <Html
        position={[0, -(radius + 0.35), 0]}
        center
        distanceFactor={8}
        zIndexRange={[5, 0]}
        style={{
          pointerEvents: "none",
          userSelect: "none",
        }}
      >
        <div
          style={{
            color: "#7f94a8",
            fontFamily:
              "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: "9px",
            whiteSpace: "nowrap",
            textAlign: "center",
            opacity: 0.9,
          }}
        >
          {(asset.type ?? "unknown").toUpperCase()}
        </div>
      </Html>
    </group>
  );
}

export default NetworkNode;
