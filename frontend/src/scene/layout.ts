/*
 * Disposition du jumeau numérique. Module pur (testé par node --test).
 *
 * - Anneau = rôle réseau : routeurs au cœur, puis serveurs, postes, inconnus en périphérie.
 * - Altitude = score de risque : plus un asset est exposé, plus il s'élève au-dessus du plan.
 * L'ordre dans un anneau suit l'adresse IP, pour que la carte reste stable d'un scan à l'autre.
 */

export type Vec3 = [number, number, number];

export type LayoutInput = { id: number; ip: string; asset_type: string; risk_score: number | null };

const RING_OF_TYPE: Record<string, number> = { router: 0, server: 1, pc: 2, iot: 2, unknown: 3 };
const RING_RADIUS = [0, 3.1, 4.8, 6.3];
const RING_PHASE = [0, -Math.PI / 2, -Math.PI / 3, -Math.PI / 4];

export const BASE_ALTITUDE = 0.55;
export const RISK_ALTITUDE = 2.4;

export function ringOf(assetType: string): number {
  return RING_OF_TYPE[assetType] ?? 3;
}

export function ipSortKey(ip: string): number {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return Number.MAX_SAFE_INTEGER;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

export function altitudeFor(risk: number | null | undefined): number {
  const clamped = Math.max(0, Math.min(100, Number(risk ?? 0)));
  return BASE_ALTITUDE + (clamped / 100) * RISK_ALTITUDE;
}

export function computeLayout(assets: LayoutInput[]): Map<number, Vec3> {
  const rings: LayoutInput[][] = [[], [], [], []];
  for (const asset of assets) rings[ringOf(asset.asset_type)].push(asset);

  const positions = new Map<number, Vec3>();
  rings.forEach((members, ring) => {
    members.sort((a, b) => ipSortKey(a.ip) - ipSortKey(b.ip) || a.id - b.id);
    // Plusieurs routeurs : ils forment un petit anneau central au lieu de se superposer
    const radius = ring === 0 && members.length > 1 ? 1.3 : RING_RADIUS[ring];
    members.forEach((asset, index) => {
      const angle = RING_PHASE[ring] + (index / Math.max(members.length, 1)) * Math.PI * 2;
      positions.set(asset.id, [
        round(Math.cos(angle) * radius),
        round(altitudeFor(asset.risk_score)),
        round(Math.sin(angle) * radius),
      ]);
    });
  });
  return positions;
}

/*
 * Point de contrôle d'un arc de Bézier quadratique entre deux assets : arc d'autant plus haut
 * que la liaison est longue. `side` (±1) écarte latéralement les deux sens d'une paire A↔B
 * pour qu'ils ne se superposent pas.
 */
export function arcControl(a: Vec3, b: Vec3, side = 0, lift = 0.22): Vec3 {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const dz = b[2] - a[2];
  const length = Math.sqrt(dx * dx + dy * dy + dz * dz);
  const planar = Math.hypot(dx, dz) || 1;
  const offset = 0.45 * side;
  return [
    round((a[0] + b[0]) / 2 + (-dz / planar) * offset),
    round(Math.max(a[1], b[1]) + 0.35 + length * lift),
    round((a[2] + b[2]) / 2 + (dx / planar) * offset),
  ];
}

/*
 * Écartement d'une liaison orientée : non nul uniquement si la liaison inverse existe.
 * Le même signe suffit pour les deux sens : la perpendiculaire calculée dans arcControl
 * s'inverse déjà avec la direction, ce qui place A→B et B→A de part et d'autre.
 */
export function linkSide(hasReverse: boolean): number {
  return hasReverse ? 1 : 0;
}

/* Position sur la courbe quadratique a → c → b pour t ∈ [0, 1]. */
export function quadraticPoint(a: Vec3, c: Vec3, b: Vec3, t: number): Vec3 {
  const u = 1 - t;
  return [
    u * u * a[0] + 2 * u * t * c[0] + t * t * b[0],
    u * u * a[1] + 2 * u * t * c[1] + t * t * b[1],
    u * u * a[2] + 2 * u * t * c[2] + t * t * b[2],
  ];
}

export const RING_RADII = RING_RADIUS;

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}
