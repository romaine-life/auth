import { test } from "node:test";
import assert from "node:assert/strict";
import { serviceUserId } from "./service-exchange-helpers.js";

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
