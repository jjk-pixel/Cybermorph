import { useState } from "react";

const API = "http://192.168.43.135:8000";

export interface SimPath {
  source: number;
  target: number;
  nodes: number[];
  score: number;
  risk: string;
  evidence_level: string;
}

export interface SimResult {
  paths_before_count: number;
  paths_after_count: number;
  new_paths_count: number;
  new_paths: SimPath[];
  paths_after: SimPath[];
  paths_before: SimPath[];
  strengthened_paths: SimPath[];
}

export function useSimulation() {
  const [result, setResult] = useState<SimResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [compromisedAssetId, setCompromisedAssetId] = useState<number | null>(null);

  async function runCompromise(assetId: number) {
    setLoading(true);
    try {
      const createRes = await fetch(`${API}/api/simulations/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `Compromission asset #${assetId}`,
          description: "Simulation What-If lancée depuis la vue 3D",
        }),
      });
      const sim = await createRes.json();

      const hypRes = await fetch(`${API}/api/simulations/${sim.id}/hypothesis`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "asset_compromised", asset_id: assetId }),
      });

      if (!hypRes.ok) throw new Error("Échec de la simulation");

      const detailRes = await fetch(`${API}/api/simulations/${sim.id}/result`);
      const detail = await detailRes.json();

      const before = detail.result.paths_before as SimPath[];
      const after = detail.result.paths_after as SimPath[];

      const strengthened = after.filter((afterPath: SimPath) => {
        const beforeMatch = before.find(
          (b) => b.source === afterPath.source && b.target === afterPath.target &&
                 JSON.stringify(b.nodes) === JSON.stringify(afterPath.nodes)
        );
        return beforeMatch && afterPath.score > beforeMatch.score + 1; // marge pour éviter le bruit d'arrondi
      });

      detail.result.strengthened_paths = strengthened;

      setResult(detail.result);
      setCompromisedAssetId(assetId);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  function clear() {
    setResult(null);
    setCompromisedAssetId(null);
  }

  return { result, loading, compromisedAssetId, runCompromise, clear };
}
