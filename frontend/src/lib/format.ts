/* Formatage et vocabulaire partagés. Module pur (testé par node --test). */

/* Les colonnes sans fuseau du backend sont en UTC : on l'explicite avant de parser. */
export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value);
  const date = new Date(hasZone ? value : `${value.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

const timeFormat = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateTimeFormat = new Intl.DateTimeFormat("fr-FR", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});

export function formatTime(value: string | null | undefined): string {
  const date = parseDate(value);
  return date ? timeFormat.format(date) : "—";
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parseDate(value);
  return date ? dateTimeFormat.format(date) : "—";
}

export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const date = parseDate(value);
  if (!date) return "jamais";
  const seconds = Math.round((now - date.getTime()) / 1000);
  if (seconds < 5) return "à l'instant";
  if (seconds < 60) return `il y a ${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `il y a ${hours} h`;
  return `il y a ${Math.round(hours / 24)} j`;
}

export function formatCount(value: number): string {
  return new Intl.NumberFormat("fr-FR").format(value);
}

export type RiskBand = "low" | "moderate" | "high" | "critical";

/* Mêmes seuils que le backend (risk_engine / graph_engine). */
export function riskBand(score: number | null | undefined): RiskBand {
  const s = Number(score ?? 0);
  if (s >= 75) return "critical";
  if (s >= 50) return "high";
  if (s >= 25) return "moderate";
  return "low";
}

export const RISK_LABEL: Record<RiskBand, string> = {
  low: "Faible",
  moderate: "Modéré",
  high: "Élevé",
  critical: "Critique",
};

/* Couleurs partagées par l'interface (CSS) et la scène (three.js). */
export const COLORS = {
  cyan: "#22e4ff",
  blue: "#2f6bff",
  violet: "#9b5cff",
  amber: "#ffc857",
  orange: "#ff8a3d",
  red: "#ff3b5c",
  muted: "#3a4658",
  ink: "#e6f4ff",
} as const;

export const RISK_COLOR: Record<RiskBand, string> = {
  low: COLORS.cyan,
  moderate: COLORS.amber,
  high: COLORS.orange,
  critical: COLORS.red,
};

export const EVIDENCE_LABEL: Record<string, string> = {
  voisinage_detecte: "Voisinage ARP",
  inferee: "Inférée",
  observee: "Trafic observé",
  alerte_ids: "Alerte IDS",
};

export const ASSET_TYPE_LABEL: Record<string, string> = {
  router: "Routeur",
  server: "Serveur",
  pc: "Poste",
  iot: "Objet connecté",
  unknown: "Inconnu",
};

export const INCIDENT_STATUS_LABEL: Record<string, string> = {
  detected: "Détecté",
  progressing: "En progression",
  dormant: "Dormant",
};

export const RISK_BREAKDOWN_LABEL: Record<string, string> = {
  exposition_reseau: "Exposition réseau",
  vulnerabilite_os: "Vulnérabilité OS",
  criticite_asset: "Criticité",
  signaux_comportementaux: "Comportement",
  fraicheur_donnees: "Fraîcheur des données",
};

/* Poids maximal de chaque critère dans risk_engine (pour dessiner des jauges justes). */
export const RISK_BREAKDOWN_MAX: Record<string, number> = {
  exposition_reseau: 30,
  vulnerabilite_os: 25,
  criticite_asset: 20,
  signaux_comportementaux: 15,
  fraicheur_donnees: 10,
};

/* Priorité Suricata : 1 = la plus sévère. */
export function priorityBand(priority: number | null | undefined): RiskBand {
  if (priority === 1) return "critical";
  if (priority === 2) return "high";
  if (priority === 3) return "moderate";
  return "low";
}

export function splitList(value: string | null | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}
