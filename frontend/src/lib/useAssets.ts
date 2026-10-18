import { useMemo } from "react";
import type { LiveAsset } from "../api/types";
import { useLive } from "../state/live";

/* Index id → asset issu du flux live, et libellé lisible d'un asset. */
export function useAssetIndex() {
  const assets = useLive((s) => s.state?.assets);
  return useMemo(() => {
    const byId = new Map<number, LiveAsset>((assets ?? []).map((a) => [a.id, a]));
    const byIp = new Map<string, LiveAsset>((assets ?? []).map((a) => [a.ip, a]));
    const label = (id: number | null | undefined) => (id == null ? "Externe" : byId.get(id)?.ip ?? `#${id}`);
    return { byId, byIp, label, list: assets ?? [] };
  }, [assets]);
}
