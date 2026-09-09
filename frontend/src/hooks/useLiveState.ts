import { useEffect, useRef, useState } from "react";

export interface Asset {
  id: number;
  ip: string;
  hostname: string;
  asset_type: string;
  risk_score: number;
  status: string;
}
export interface Edge {
  source: number; target: number; connection_type: string; protocol: string;
}
export interface AttackPath {
  source: number; target: number; score: number; risk: string; evidence_level: string;
}
export interface IncidentStep {
  source_asset_id: number;
  destination_asset_id: number;
  status: string; // "potential" | "confirmed"
  confidence: number;
}

export interface ActiveIncident {
  incident_id: number;
  status: string;
  source_asset_id: number | null;
  current_asset_id: number;
  target_asset_id: number | null;
  confidence: number;
  current_step: number;
  total_steps: number;
  steps: IncidentStep[];
}

export interface LiveState {
  assets: Asset[];
  edges: Edge[];
  attack_paths: AttackPath[];
  active_incidents: ActiveIncident[];
}
const WS_URL = "ws://192.168.43.135:8000/ws/live";

export function useLiveState() {
  const [state, setState] = useState<LiveState | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "state_update") setState(data);
      };
    }
    connect();
    return () => wsRef.current?.close();
  }, []);

  return { state, connected };
}
