import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { QuadraticBezierLine } from "@react-three/drei";
import type { Mesh } from "three";
import { COLORS } from "../lib/format";
import { arcControl, quadraticPoint, type Vec3 } from "./layout";
import type { SceneLink, Trace } from "./useSceneModel";

const TRACE_STYLE: Record<Trace["kind"], { color: string; width: number; dashed: boolean; pulse: boolean; opacity: number }> = {
  predicted: { color: COLORS.violet, width: 3.2, dashed: false, pulse: true, opacity: 0.95 },
  simulated: { color: COLORS.violet, width: 2.4, dashed: true, pulse: true, opacity: 0.85 },
  "incident-confirmed": { color: COLORS.red, width: 3, dashed: false, pulse: true, opacity: 0.95 },
  "incident-potential": { color: COLORS.red, width: 1.2, dashed: true, pulse: false, opacity: 0.4 },
};

type Hop = { from: Vec3; mid: Vec3; to: Vec3 };

/*
 * Trace d'un chemin (prédit, simulé ou d'incident) par-dessus les liaisons.
 * Une impulsion lumineuse parcourt les sauts dans l'ordre, de l'origine vers la cible.
 */
export function PathTrace({
  trace, positions, linkIndex, animate,
}: { trace: Trace; positions: Map<number, Vec3>; linkIndex: Map<string, SceneLink>; animate: boolean }) {
  const style = TRACE_STYLE[trace.kind];
  const pulse = useRef<Mesh>(null);

  const hops: Hop[] = useMemo(() => {
    const result: Hop[] = [];
    for (let i = 0; i < trace.nodes.length - 1; i += 1) {
      const from = positions.get(trace.nodes[i]);
      const to = positions.get(trace.nodes[i + 1]);
      if (!from || !to) continue;
      const link = linkIndex.get(`${trace.nodes[i]}>${trace.nodes[i + 1]}`);
      const base = link?.mid ?? arcControl(from, to);
      // Légèrement au-dessus de la liaison pour rester lisible
      result.push({ from, to, mid: [base[0], base[1] + 0.06, base[2]] });
    }
    return result;
  }, [trace.nodes, positions, linkIndex]);

  useFrame(({ clock }) => {
    if (!pulse.current || hops.length === 0) return;
    const progress = (clock.elapsedTime * 0.45) % hops.length;
    const hop = hops[Math.floor(progress)];
    const [x, y, z] = quadraticPoint(hop.from, hop.mid, hop.to, progress % 1);
    pulse.current.position.set(x, y, z);
  });

  if (hops.length === 0) return null;

  return (
    <group>
      {hops.map((hop, i) => (
        <QuadraticBezierLine
          key={i}
          start={hop.from}
          end={hop.to}
          mid={hop.mid}
          color={style.color}
          lineWidth={style.width}
          dashed={style.dashed}
          dashSize={0.16}
          gapSize={0.1}
          transparent
          opacity={style.opacity}
        />
      ))}
      {style.pulse && animate && (
        <mesh ref={pulse}>
          <sphereGeometry args={[0.09, 16, 16]} />
          <meshBasicMaterial color={style.color} toneMapped={false} />
        </mesh>
      )}
    </group>
  );
}
