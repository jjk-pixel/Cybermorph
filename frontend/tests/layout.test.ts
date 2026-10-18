import { test } from "node:test";
import assert from "node:assert/strict";
import {
  altitudeFor, arcControl, BASE_ALTITUDE, computeLayout, ipSortKey, linkSide, quadraticPoint, RING_RADII, RISK_ALTITUDE, ringOf,
} from "../src/scene/layout.ts";

const radius = ([x, , z]: number[]) => Math.hypot(x, z);

test("chaque rôle a son anneau, les types inconnus vont en périphérie", () => {
  assert.equal(ringOf("router"), 0);
  assert.equal(ringOf("server"), 1);
  assert.equal(ringOf("pc"), 2);
  assert.equal(ringOf("unknown"), 3);
  assert.equal(ringOf("imprimante"), 3);
});

test("routeur unique au centre, serveurs sur leur anneau", () => {
  const layout = computeLayout([
    { id: 1, ip: "192.168.43.2", asset_type: "router", risk_score: 20 },
    { id: 2, ip: "192.168.43.10", asset_type: "server", risk_score: 30 },
    { id: 3, ip: "192.168.43.11", asset_type: "server", risk_score: 30 },
    { id: 4, ip: "192.168.43.254", asset_type: "unknown", risk_score: 0 },
  ]);
  assert.equal(radius(layout.get(1)!), 0);
  assert.ok(Math.abs(radius(layout.get(2)!) - RING_RADII[1]) < 0.01);
  assert.ok(Math.abs(radius(layout.get(4)!) - RING_RADII[3]) < 0.01);
});

test("plusieurs routeurs ne se superposent pas", () => {
  const layout = computeLayout([
    { id: 1, ip: "10.0.0.1", asset_type: "router", risk_score: 0 },
    { id: 2, ip: "10.0.0.2", asset_type: "router", risk_score: 0 },
  ]);
  assert.notDeepEqual(layout.get(1), layout.get(2));
});

test("l'altitude croît avec le risque et reste bornée", () => {
  assert.equal(altitudeFor(0), BASE_ALTITUDE);
  assert.equal(altitudeFor(100), BASE_ALTITUDE + RISK_ALTITUDE);
  assert.equal(altitudeFor(250), BASE_ALTITUDE + RISK_ALTITUDE);
  assert.equal(altitudeFor(null), BASE_ALTITUDE);
  assert.ok(altitudeFor(60) > altitudeFor(30));
});

test("la disposition est stable : même entrée dans un ordre différent, mêmes positions", () => {
  const assets = [
    { id: 5, ip: "192.168.43.135", asset_type: "server", risk_score: 28 },
    { id: 1, ip: "192.168.43.1", asset_type: "server", risk_score: 20 },
    { id: 6, ip: "192.168.43.133", asset_type: "server", risk_score: 32 },
  ];
  const a = computeLayout(assets);
  const b = computeLayout([...assets].reverse());
  for (const asset of assets) assert.deepEqual(a.get(asset.id), b.get(asset.id));
});

test("tri numérique des IP (et non lexical)", () => {
  assert.ok(ipSortKey("192.168.43.2") < ipSortKey("192.168.43.10"));
  assert.equal(ipSortKey("pas-une-ip"), Number.MAX_SAFE_INTEGER);
});

test("les deux sens d'une paire sont écartés de part et d'autre", () => {
  const a: [number, number, number] = [0, 1, 0];
  const b: [number, number, number] = [4, 1, 0];
  assert.equal(linkSide(false), 0);
  const forward = arcControl(a, b, linkSide(true));
  const backward = arcControl(b, a, linkSide(true));
  // Les points de contrôle doivent tomber de part et d'autre de l'axe A–B (z de signes opposés)
  assert.ok(forward[2] * backward[2] < 0, `forward=${forward} backward=${backward}`);
  assert.ok(forward[1] > 1, "l'arc passe au-dessus des nœuds");
});

test("la courbe quadratique passe par ses extrémités", () => {
  const a: [number, number, number] = [0, 0, 0];
  const c: [number, number, number] = [1, 2, 0];
  const b: [number, number, number] = [2, 0, 0];
  assert.deepEqual(quadraticPoint(a, c, b, 0), a);
  assert.deepEqual(quadraticPoint(a, c, b, 1), b);
  assert.deepEqual(quadraticPoint(a, c, b, 0.5), [1, 1, 0]);
});
