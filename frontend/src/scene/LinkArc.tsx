import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { QuadraticBezierLine } from "@react-three/drei";
import type { Mesh } from "three";
import { COLORS } from "../lib/format";
import { quadraticPoint, type Vec3 } from "./layout";
import type { SceneLink } from "./useSceneModel";

/* Couleur d'une liaison selon la solidité de la preuve qui l'établit. */
const EVIDENCE_COLOR: Record<string, string> = {
  voisinage_detecte: COLORS.blue,
  inferee: COLORS.blue,
  observee: COLORS.cyan,
  alerte_ids: COLORS.amber,
};

/* Particules circulant de la source vers la cible ; vitesse proportionnelle au poids de transition. */
function Flow({ from, mid, to, color, weight, count }: { from: Vec3; mid: Vec3; to: Vec3; color: string; weight: number; count: number }) {
  const refs = useRef<(Mesh | null)[]>([]);
  const offsets = useMemo(() => Array.from({ length: count }, (_, i) => i / count), [count]);
  const speed = 0.08 + (weight / 100) * 0.32;

  useFrame(({ clock }) => {
    offsets.forEach((offset, i) => {
      const mesh = refs.current[i];
      if (!mesh) return;
      const t = (clock.elapsedTime * speed + offset) % 1;
      const [x, y, z] = quadraticPoint(from, mid, to, t);
      mesh.position.set(x, y, z);
    });
  });

  return (
    <>
      {offsets.map((_, i) => (
        <mesh key={i} ref={(m) => { refs.current[i] = m; }}>
          <sphereGeometry args={[0.035, 8, 8]} />
          <meshBasicMaterial color={color} toneMapped={false} />
        </mesh>
      ))}
    </>
  );
}

export function LinkArc({ link, dimmed, animate }: { link: SceneLink; dimmed: boolean; animate: boolean }) {
  const color = link.removed ? COLORS.muted : EVIDENCE_COLOR[link.evidence_level] ?? COLORS.blue;
  const weak = link.evidence_level === "voisinage_detecte" || link.evidence_level === "inferee";
  const opacity = link.removed ? 0.35 : dimmed ? 0.12 : weak ? 0.35 : 0.65;

  return (
    <group>
      <QuadraticBezierLine
        start={link.from}
        end={link.to}
        mid={link.mid}
        color={color}
        lineWidth={link.evidence_level === "alerte_ids" ? 1.8 : 1.1}
        dashed={weak || link.removed}
        dashSize={0.12}
        gapSize={0.1}
        transparent
        opacity={opacity}
      />
      {animate && !link.removed && !dimmed && (
        <Flow from={link.from} mid={link.mid} to={link.to} color={color} weight={link.weight} count={weak ? 1 : 3} />
      )}
    </group>
  );
}
