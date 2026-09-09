export type ViewName = "3d" | "alerts" | "paths" | "mitre" | "timeline";

interface Props {
  current: ViewName;
  onChange: (v: ViewName) => void;
}

const ITEMS: { id: ViewName; label: string }[] = [
  { id: "3d", label: "Vue 3D" },
  { id: "alerts", label: "Alertes" },
  { id: "paths", label: "Chemins d'attaque" },
  { id: "mitre", label: "MITRE ATT&CK" },
  { id: "timeline", label: "Timeline" },
];

export default function Sidebar({ current, onChange }: Props) {
  return (
    <div className="sidebar">
      <div className="brand">CYBERMORPH</div>
      <nav>
        {ITEMS.map((item) => (
          <button
            key={item.id}
            className={current === item.id ? "active" : ""}
            onClick={() => onChange(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </div>
  );
}
