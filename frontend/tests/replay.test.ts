import { test } from "node:test";
import assert from "node:assert/strict";
import { linksFromSnapshot } from "../src/scene/replay.ts";

test("une paire = une liaison, qui vaut sa preuve la plus forte", () => {
  const links = linksFromSnapshot([
    { source: 2, target: 1, connection_type: "neighbor_detected", protocol: "arp", port: null, origin: null, last_seen: "2026-10-18T00:51:02+00:00" },
    { source: 2, target: 1, connection_type: "detected", protocol: "tcp", port: 53, origin: null, last_seen: "2026-09-01T22:15:04+00:00" },
    { source: 1, target: 4, connection_type: "detected", protocol: "udp", port: 67, origin: "suricata_flow", last_seen: "2026-10-18T00:48:52+00:00" },
  ]);
  assert.equal(links.length, 2);
  const pair = links.find((l) => l.source === 2)!;
  assert.equal(pair.evidence_level, "observee");
  assert.deepEqual(pair.provenance, { observed: true, inferred: true, declared: false, ids: false });
  assert.deepEqual(pair.observed_sources, ["historique"]);
  assert.equal(pair.last_seen, "2026-10-18T00:51:02+00:00");
  assert.deepEqual(links.find((l) => l.source === 1)!.observed_sources, ["suricata_flow"]);
});

test("une relation seulement déclarée reste distinguable", () => {
  const [link] = linksFromSnapshot([
    { source: 1, target: 2, connection_type: "declared", protocol: "tcp", port: 443, origin: "operator", last_seen: null },
  ]);
  assert.equal(link.provenance.declared, true);
  assert.equal(link.provenance.observed, false);
});
