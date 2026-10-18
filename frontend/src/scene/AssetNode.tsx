import { useRef } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import { Edges, Html, Line } from "@react-three/drei";
import type { Mesh } from "three";
import type { LiveAsset } from "../api/types";
import { ASSET_TYPE_LABEL, COLORS, RISK_COLOR, riskBand } from "../lib/format";
import type { Vec3 } from "./layout";

type Props = {
  asset: LiveAsset;
  position: Vec3;
  selected: boolean;
  hovered: boolean;
  dimmed: boolean;
  underAttack: boolean;
  compromised: boolean;
  exposed: boolean;
  /* actif critique : "declared" ou "inferred" (null sinon) */
  critical: "declared" | "inferred" | null;
  /* point de blocage des chemins d'attaque */
  choke: boolean;
  /* actif non autorisé (apparu après l'apprentissage ou déclaré comme tel) */
  unauthorized: boolean;
  animate: boolean;
  onSelect: (id: number) => void;
  onHover: (id: number | null) => void;
};

function Shape({ type }: { type: string }) {
  switch (type) {
    case "router":
      return <octahedronGeometry args={[0.42, 0]} />;
    case "server":
      return <cylinderGeometry args={[0.28, 0.28, 0.62, 6]} />;
    case "pc":
    case "iot":
      return <boxGeometry args={[0.42, 0.42, 0.42]} />;
    default:
      return <icosahedronGeometry args={[0.27, 0]} />;
  }
}

export function AssetNode({
  asset, position, selected, hovered, dimmed, underAttack, compromised, exposed, critical, choke, unauthorized, animate, onSelect, onHover,
}: Props) {
  const body = useRef<Mesh>(null);
  const shell = useRef<Mesh>(null);

  const down = asset.status === "down";
  const risk = Number(asset.risk_score ?? 0);
  const color = down ? COLORS.muted : RISK_COLOR[riskBand(risk)];
  const shellColor = compromised ? COLORS.violet : underAttack ? COLORS.red : null;
  const opacity = dimmed ? 0.28 : down ? 0.45 : 1;

  useFrame(({ clock }, delta) => {
    if (!animate) return;
    if (body.current && asset.asset_type === "router") body.current.rotation.y += delta * 0.35;
    if (shell.current) {
      const pulse = 1 + 0.12 * Math.sin(clock.elapsedTime * 3.2);
      shell.current.scale.setScalar(pulse);
    }
  });

  const stop = (event: ThreeEvent<PointerEvent | MouseEvent>) => event.stopPropagation();

  return (
    <group position={position}>
      {/* Tige jusqu'au plan : l'altitude du nœud encode son score de risque */}
      <Line
        points={[[0, -0.32, 0], [0, -position[1], 0]]}
        color={color}
        lineWidth={1}
        transparent
        opacity={0.25 * opacity}
        dashed
        dashSize={0.06}
        gapSize={0.06}
      />

      <mesh
        ref={body}
        onClick={(e) => { stop(e); onSelect(asset.id); }}
        onPointerOver={(e) => { stop(e); onHover(asset.id); document.body.style.cursor = "pointer"; }}
        onPointerOut={() => { onHover(null); document.body.style.cursor = ""; }}
      >
        <Shape type={asset.asset_type} />
        <meshStandardMaterial
          color="#06121f"
          emissive={color}
          emissiveIntensity={selected ? 1.1 : hovered ? 0.8 : down ? 0.08 : 0.42}
          metalness={0.4}
          roughness={0.35}
          transparent
          opacity={opacity}
        />
        <Edges color={selected ? COLORS.ink : color} threshold={15} />
      </mesh>

      {/* Auréole de risque : la longueur de l'arc vaut le score (0 → 100) */}
      <group rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.36, 0]}>
        <mesh>
          <ringGeometry args={[0.52, 0.55, 64]} />
          <meshBasicMaterial color={COLORS.blue} transparent opacity={0.18 * opacity} depthWrite={false} />
        </mesh>
        {risk > 0 && (
          <mesh rotation={[0, 0, Math.PI / 2]}>
            <ringGeometry args={[0.5, 0.57, 64, 1, 0, (Math.min(risk, 100) / 100) * Math.PI * 2]} />
            <meshBasicMaterial color={color} transparent opacity={0.9 * opacity} depthWrite={false} toneMapped={false} />
          </mesh>
        )}
      </group>

      {selected && (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -position[1] + 0.01, 0]}>
          <ringGeometry args={[0.62, 0.7, 64]} />
          <meshBasicMaterial color={COLORS.blue} transparent opacity={0.7} toneMapped={false} />
        </mesh>
      )}

      {shellColor && (
        <mesh ref={shell}>
          <sphereGeometry args={[0.62, 24, 16]} />
          <meshBasicMaterial color={shellColor} wireframe transparent opacity={0.35} toneMapped={false} />
        </mesh>
      )}

      {/* Couronne : actif critique, pleine si la criticité est déclarée, estompée si elle est inférée */}
      {critical && (
        <mesh position={[0, 0.5, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <torusGeometry args={[0.2, 0.018, 8, 6]} />
          <meshBasicMaterial color={COLORS.ink} transparent opacity={(critical === "declared" ? 0.95 : 0.5) * opacity} toneMapped={false} />
        </mesh>
      )}

      {/* Point de blocage : octogone violet au sol (calculé sur les chemins prédits) */}
      {choke && (
        <mesh rotation={[-Math.PI / 2, 0, Math.PI / 8]} position={[0, -position[1] + 0.02, 0]}>
          <ringGeometry args={[0.8, 0.86, 8]} />
          <meshBasicMaterial color={COLORS.violet} transparent opacity={0.85 * opacity} toneMapped={false} />
        </mesh>
      )}

      {/* Non autorisé : anneau ambre discontinu autour du nœud */}
      {unauthorized && (
        <group rotation={[-Math.PI / 2, 0, 0]}>
          {Array.from({ length: 6 }, (_, i) => (
            <mesh key={i}>
              <ringGeometry args={[0.66, 0.71, 12, 1, (i * Math.PI) / 3, Math.PI / 5]} />
              <meshBasicMaterial color={COLORS.amber} transparent opacity={0.9 * opacity} toneMapped={false} side={2} />
            </mesh>
          ))}
        </group>
      )}

      {exposed && (
        <mesh position={[0, 0.62, 0]} rotation={[Math.PI, 0, 0]}>
          <coneGeometry args={[0.1, 0.2, 4]} />
          <meshBasicMaterial color={COLORS.violet} toneMapped={false} />
        </mesh>
      )}

      <Html position={[0, 0.72, 0]} center zIndexRange={[20, 0]} style={{ pointerEvents: "none" }}>
        <div className={`node-label${selected ? " is-selected" : ""}${dimmed ? " is-dimmed" : ""}${down ? " is-down" : ""}`}>
          <span className="node-label-ip">{asset.ip}</span>
          {(hovered || selected) && (
            <span className="node-label-meta">
              {asset.hostname && asset.hostname !== asset.ip ? asset.hostname : ASSET_TYPE_LABEL[asset.asset_type] ?? asset.asset_type}
              {down ? " · hors ligne" : ""}
              {unauthorized ? " · non autorisé" : ""}
              {asset.is_scanner ? " · scanner" : ""}
            </span>
          )}
        </div>
      </Html>
    </group>
  );
}
