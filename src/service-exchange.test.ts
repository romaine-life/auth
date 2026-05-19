import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isPlausibleActorEmail,
  serviceUserId,
} from "./service-exchange-helpers.js";

// End-to-end exchange (verify → annotation → upsert → mint) is exercised
// by tank-operator's integration path in #486 stage 2. Unit coverage here
// focuses on the pure helpers — the userId derivation rule that pins the
// synthetic-email/sub/audit triangle. The JWT-shape contract moved to
// src/mint-jwt-helpers.test.ts when every mint site was unified behind
// `mintAuthJwt` (this PR).

test("serviceUserId: structured prefix isolates service users from any human UUID", () => {
  assert.strictEqual(serviceUserId("tank", "session-abc"), "svc:tank:session-abc");
});

test("serviceUserId: deterministic — same input produces same id (idempotent upsert key)", () => {
  const a = serviceUserId("tank", "session-abc");
  const b = serviceUserId("tank", "session-abc");
  assert.strictEqual(a, b);
});

// isPlausibleActorEmail is the route-boundary check for the
// on-behalf-of mint path used by elevated consumers (today: the
// tank-operator orchestrator's mcp-github proxy). The privilege gate
// (consumer.allowActorOverride) is the actual security boundary; this
// regex exists to keep obvious garbage out of the JWT claim so
// downstream consumers (mcp-github → /api/internal/github/installation
// → profile lookup) don't have to.

test("isPlausibleActorEmail accepts canonical emails", () => {
  assert.strictEqual(isPlausibleActorEmail("alice@example.com"), true);
  assert.strictEqual(isPlausibleActorEmail("nelson.gripshover@romaine.life"), true);
  assert.strictEqual(isPlausibleActorEmail("a+b@c.io"), true);
});

test("isPlausibleActorEmail trims surrounding whitespace", () => {
  assert.strictEqual(isPlausibleActorEmail("  alice@example.com  "), true);
});

test("isPlausibleActorEmail rejects empty / missing pieces", () => {
  for (const value of [
    "",
    "   ",
    "alice",
    "alice@",
    "@example.com",
    "alice@example",
    "no spaces allowed@example.com",
    "two@@signs.com",
  ]) {
    assert.strictEqual(
      isPlausibleActorEmail(value),
      false,
      `should reject ${JSON.stringify(value)}`,
    );
  }
});
