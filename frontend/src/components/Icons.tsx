import type { SVGProps } from "react";

/* Pictogrammes au trait, dessinés pour CYBERMORPH (grille 20×20). */
type IconProps = SVGProps<SVGSVGElement>;

const base = (props: IconProps) => ({
  width: 20,
  height: 20,
  viewBox: "0 0 20 20",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
  ...props,
});

export const IconTwin = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="10" cy="10" r="2" />
    <ellipse cx="10" cy="10" rx="8" ry="3.4" />
    <ellipse cx="10" cy="10" rx="3.4" ry="8" />
  </svg>
);

/* Cible protégée : actif critique au centre, chemins coupés autour */
export const IconExposure = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="10" cy="10" r="2.2" />
    <path d="M10 2.5a7.5 7.5 0 0 1 7.5 7.5M17.5 10a7.5 7.5 0 0 1-5 7.07M7.5 17.07A7.5 7.5 0 0 1 2.5 10M2.5 10a7.5 7.5 0 0 1 5-7.07" />
  </svg>
);

/* Inventaire : fiches empilées, la première annotée */
export const IconInventory = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="3" y="3" width="14" height="4" rx="1" />
    <rect x="3" y="8.5" width="14" height="4" rx="1" />
    <rect x="3" y="14" width="14" height="3" rx="1" />
    <path d="M6 5h2M6 10.5h2" />
  </svg>
);

export const IconAlert = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M10 2.5 18 17H2z" />
    <path d="M10 8v4M10 14.6v.1" />
  </svg>
);

export const IconIncident = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="4" cy="15" r="1.6" />
    <circle cx="10" cy="6" r="1.6" />
    <circle cx="16" cy="12" r="1.6" />
    <path d="M5 13.6 9 7.4M11.4 6.8l3.4 4" />
  </svg>
);

export const IconPath = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M3 16c3-8 6 0 9-6s3-6 5-7" />
    <path d="M14 3h3v3" />
  </svg>
);

export const IconMatrix = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="2.5" y="2.5" width="4" height="4" />
    <rect x="8" y="2.5" width="4" height="4" />
    <rect x="13.5" y="2.5" width="4" height="4" />
    <rect x="2.5" y="8" width="4" height="4" />
    <rect x="8" y="8" width="4" height="4" fill="currentColor" />
    <rect x="2.5" y="13.5" width="4" height="4" />
    <rect x="13.5" y="13.5" width="4" height="4" fill="currentColor" />
  </svg>
);

export const IconTimeline = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M2 14h3l2.5-6 3 9 2.5-7 1.5 4H18" />
  </svg>
);

export const IconSimulation = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M7 2.5h6M8 2.5v5L3.5 15.5A1.4 1.4 0 0 0 4.7 17.5h10.6a1.4 1.4 0 0 0 1.2-2L12 7.5v-5" />
    <path d="M5.6 12h8.8" />
  </svg>
);

export const IconClose = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="m5 5 10 10M15 5 5 15" />
  </svg>
);

export const IconRecenter = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="10" cy="10" r="2.5" />
    <path d="M10 2v3M10 15v3M2 10h3M15 10h3" />
  </svg>
);

export const IconPlan = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="m10 3 7 3.5-7 3.5-7-3.5z" />
    <path d="m3 10 7 3.5 7-3.5M3 13.5 10 17l7-3.5" />
  </svg>
);

export function BrandMark(p: IconProps) {
  return (
    <svg width="34" height="34" viewBox="0 0 34 34" fill="none" aria-hidden {...p}>
      <path d="M17 2 30 9.5v15L17 32 4 24.5v-15z" stroke="var(--blue)" strokeWidth="1.4" />
      <path d="M17 8.5 24.4 12.8v8.4L17 25.5l-7.4-4.3v-8.4z" stroke="var(--cyan)" strokeWidth="1.4" />
      <circle cx="17" cy="17" r="2.4" fill="var(--violet)" />
    </svg>
  );
}
