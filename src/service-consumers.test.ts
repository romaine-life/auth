import { test } from "node:test";
import assert from "node:assert/strict";
import { consumerForNamespace } from "./service-consumers.js";

test("consumerForNamespace maps prod tank orchestrator to elevated pod-stable consumer", () => {
  assert.deepStrictEqual(consumerForNamespace("tank-operator"), {
    slug: "tank-operator",
    mode: "pod-stable",
    stableId: "orchestrator",
    allowActorOverride: true,
  });
});

test("consumerForNamespace maps tank test slots to elevated pod-stable consumers", () => {
  assert.deepStrictEqual(consumerForNamespace("tank-operator-slot-5"), {
    slug: "tank-operator",
    mode: "pod-stable",
    stableId: "orchestrator-slot-5",
    allowActorOverride: true,
  });
});

test("consumerForNamespace maps glimmung to pod-stable consumer", () => {
  assert.deepStrictEqual(consumerForNamespace("glimmung"), {
    slug: "glimmung",
    mode: "pod-stable",
    stableId: "glimmung",
  });
});

test("consumerForNamespace maps tank test-slot sessions to per-session consumers", () => {
  assert.deepStrictEqual(consumerForNamespace("tank-operator-slot-5-sessions"), {
    slug: "tank",
    mode: "per-session",
    sessionIdPrefix: "slot-5-session-",
  });
});

test("consumerForNamespace rejects non-canonical tank slot namespaces", () => {
  assert.strictEqual(consumerForNamespace("tank-operator-slot-0"), undefined);
  assert.strictEqual(consumerForNamespace("tank-operator-slot-alpha"), undefined);
  assert.strictEqual(consumerForNamespace("other-slot-5"), undefined);
  assert.strictEqual(consumerForNamespace("tank-operator-slot-0-sessions"), undefined);
  assert.strictEqual(consumerForNamespace("tank-operator-slot-alpha-sessions"), undefined);
  assert.strictEqual(consumerForNamespace("other-slot-5-sessions"), undefined);
});
