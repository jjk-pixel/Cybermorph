import { test } from "node:test";
import assert from "node:assert/strict";
import { api, ApiError } from "../src/api/client.ts";

type FetchImpl = typeof globalThis.fetch;

async function withFetch<T>(impl: FetchImpl, run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await run();
  } finally {
    globalThis.fetch = original;
  }
}

const json = (status: number, body: unknown) =>
  (async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })) as FetchImpl;

test("une réponse vide reste une liste vide, pas une erreur", async () => {
  const rows = await withFetch(json(200, []), () => api.correlations());
  assert.deepEqual(rows, []);
});

test("un backend injoignable donne une erreur explicite (statut 0)", async () => {
  const failing = (async () => { throw new TypeError("fetch failed"); }) as FetchImpl;
  await assert.rejects(withFetch(failing, () => api.systemHealth()), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 0);
    assert.match(e.message, /injoignable/);
    return true;
  });
});

test("le détail d'une erreur JSON est conservé ; une écriture distante refusée est lisible", async () => {
  await assert.rejects(withFetch(json(403, { detail: "Opération d'écriture refusée" }), () => api.decideFinding(1, "confirmed", "vérifié")),
    (e: unknown) => e instanceof ApiError && e.status === 403 && e.message === "Opération d'écriture refusée");
  await assert.rejects(withFetch(json(500, { detail: "Erreur interne du serveur" }), () => api.alerts()),
    (e: unknown) => e instanceof ApiError && e.message === "Erreur interne du serveur");
});

test("les paramètres de filtre sont transmis dans l'URL", async () => {
  let url = "";
  const spy = (async (input: RequestInfo | URL) => { url = String(input); return new Response("[]", { status: 200 }); }) as FetchImpl;
  await withFetch(spy, () => api.vulnerabilities({ asset_id: 3, status: "probable" }));
  assert.equal(url, "/api/vulnerabilities/?asset_id=3&status=probable");
});
