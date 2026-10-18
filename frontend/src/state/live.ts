/*
 * Flux temps réel : /ws/live pousse l'état complet toutes les 5 s.
 * Reconnexion avec backoff ; en attendant, repli sur GET /api/live/state.
 */
import { api, liveSocketUrl } from "../api/client";
import type { LiveState } from "../api/types";
import { createStore, useStore } from "./createStore";

export type LinkStatus = "connecting" | "live" | "polling" | "offline";

type LiveStore = {
  state: LiveState | null;
  status: LinkStatus;
  error: string | null;
  receivedAt: number | null;
};

export const liveStore = createStore<LiveStore>({ state: null, status: "connecting", error: null, receivedAt: null });

export const useLive = <S>(selector: (s: LiveStore) => S) => useStore(liveStore, selector);

let socket: WebSocket | null = null;
let retryTimer: number | undefined;
let pollTimer: number | undefined;
let attempts = 0;
let started = false;

function accept(state: LiveState) {
  liveStore.set({ state, error: null, receivedAt: Date.now() });
}

async function pollOnce() {
  try {
    accept(await api.liveState());
    if (liveStore.get().status !== "live") liveStore.set({ status: "polling" });
  } catch (error) {
    liveStore.set({ status: "offline", error: (error as Error).message });
  }
}

function startPolling() {
  if (pollTimer !== undefined) return;
  void pollOnce();
  pollTimer = window.setInterval(pollOnce, 10_000);
}

function stopPolling() {
  window.clearInterval(pollTimer);
  pollTimer = undefined;
}

function connect() {
  liveStore.set((s) => ({ status: s.state ? s.status : "connecting" }));
  socket = new WebSocket(liveSocketUrl());

  socket.onopen = () => {
    attempts = 0;
    stopPolling();
    liveStore.set({ status: "live", error: null });
  };

  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      if (message.type === "state_update") accept(message as LiveState);
      else if (message.type === "error") liveStore.set({ error: `Calcul de l'état live : ${message.detail}` });
    } catch {
      liveStore.set({ error: "Message temps réel illisible." });
    }
  };

  socket.onclose = (event) => {
    socket = null;
    if (event.code === 4401) {
      liveStore.set({ status: "offline", error: "Accès refusé au flux temps réel : jeton d'API invalide." });
      return;
    }
    startPolling();
    attempts += 1;
    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempts, 5));
    retryTimer = window.setTimeout(connect, delay);
  };
}

export function startLive() {
  if (started) return;
  started = true;
  connect();
}

/* Demande au serveur un recalcul immédiat (après une action de l'utilisateur). */
export function requestRefresh() {
  if (socket?.readyState === WebSocket.OPEN) socket.send("refresh");
  else void pollOnce();
}

export function stopLive() {
  started = false;
  window.clearTimeout(retryTimer);
  stopPolling();
  if (socket) {
    socket.onclose = null;
    socket.close();
    socket = null;
  }
}
