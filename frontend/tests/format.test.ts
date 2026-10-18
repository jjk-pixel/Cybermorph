import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatBytes, formatRelative, isCriticalLevel, isStale, parseDate, priorityBand, riskBand, severityBand, splitList,
} from "../src/lib/format.ts";

test("une date sans fuseau est lue comme UTC", () => {
  assert.equal(parseDate("2026-10-17T15:09:22.413464")!.toISOString(), "2026-10-17T15:09:22.413Z");
  assert.equal(parseDate("2026-10-17 15:09:22")!.toISOString(), "2026-10-17T15:09:22.000Z");
});

test("une date avec fuseau est respectée", () => {
  assert.equal(parseDate("2026-10-17T15:40:54Z")!.toISOString(), "2026-10-17T15:40:54.000Z");
  assert.equal(parseDate("2026-10-17T17:40:54+02:00")!.toISOString(), "2026-10-17T15:40:54.000Z");
});

test("dates absentes ou invalides", () => {
  assert.equal(parseDate(null), null);
  assert.equal(parseDate(""), null);
  assert.equal(parseDate("n'importe quoi"), null);
});

test("seuils de risque identiques au backend (25 / 50 / 75)", () => {
  assert.equal(riskBand(0), "low");
  assert.equal(riskBand(24.9), "low");
  assert.equal(riskBand(25), "moderate");
  assert.equal(riskBand(50), "high");
  assert.equal(riskBand(75), "critical");
  assert.equal(riskBand(null), "low");
});

test("priorité Suricata : 1 est la plus sévère", () => {
  assert.equal(priorityBand(1), "critical");
  assert.equal(priorityBand(2), "high");
  assert.equal(priorityBand(3), "moderate");
  assert.equal(priorityBand(null), "low");
});

test("durées relatives", () => {
  const now = Date.parse("2026-10-17T16:00:00Z");
  assert.equal(formatRelative("2026-10-17T15:59:58Z", now), "à l'instant");
  assert.equal(formatRelative("2026-10-17T15:55:00Z", now), "il y a 5 min");
  assert.equal(formatRelative("2026-10-17T13:00:00Z", now), "il y a 3 h");
  assert.equal(formatRelative(null, now), "jamais");
});

test("listes séparées par des virgules", () => {
  assert.deepEqual(splitList("22, 80,,443 "), ["22", "80", "443"]);
  assert.deepEqual(splitList(null), []);
});

test("formatBytes et fraîcheur des observations", () => {
  assert.equal(formatBytes(512), "512 o");
  assert.equal(formatBytes(1536), "1.5 Ko");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 Mo");
  const now = Date.parse("2026-10-18T12:00:00Z");
  assert.equal(isStale("2026-10-17T11:00:00Z", now), true);
  assert.equal(isStale("2026-10-18T11:00:00Z", now), false);
  assert.equal(isStale(null, now), false);
});

test("sévérité d'un changement → bande de couleur", () => {
  assert.equal(severityBand("warning"), "high");
  assert.equal(severityBand("notice"), "moderate");
  assert.equal(severityBand("info"), "low");
  assert.equal(isCriticalLevel("high"), true);
  assert.equal(isCriticalLevel("medium"), false);
});
