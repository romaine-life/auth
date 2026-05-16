import { test } from "node:test";
import assert from "node:assert/strict";
import { extractExpClaim, serviceUserId } from "./service-exchange-helpers.js";

// End-to-end exchange (verify → annotation → upsert → mint) is exercised
// by tank-operator's integration path in #486 stage 2. Unit coverage here
// focuses on the pure helpers — the JWT-shape contract and the userId
// derivation rule that pins the synthetic-email/sub/audit triangle.

test("serviceUserId: structured prefix isolates service users from any human UUID", () => {
  assert.strictEqual(serviceUserId("tank", "session-abc"), "svc:tank:session-abc");
});

test("serviceUserId: deterministic — same input produces same id (idempotent upsert key)", () => {
  const a = serviceUserId("tank", "session-abc");
  const b = serviceUserId("tank", "session-abc");
  assert.strictEqual(a, b);
});

test("extractExpClaim: decodes the exp claim from a well-formed JWT", () => {
  // header.payload.signature — payload is base64url-encoded JSON {exp: 1234567890}
  const payload = Buffer.from(JSON.stringify({ exp: 1234567890 })).toString("base64url");
  const jwt = `header.${payload}.signature`;
  assert.strictEqual(extractExpClaim(jwt), 1234567890);
});

test("extractExpClaim: throws on a malformed JWT (wrong segment count)", () => {
  assert.throws(() => extractExpClaim("only.two"), /malformed JWT/);
  assert.throws(() => extractExpClaim("four.segments.is.too.many"), /malformed JWT/);
});

test("extractExpClaim: throws when exp is not numeric (defensive against signer bugs)", () => {
  const payload = Buffer.from(JSON.stringify({ exp: "not-a-number" })).toString("base64url");
  const jwt = `header.${payload}.signature`;
  assert.throws(() => extractExpClaim(jwt), /missing numeric exp claim/);
});

test("extractExpClaim: throws when exp is absent", () => {
  const payload = Buffer.from(JSON.stringify({ sub: "x" })).toString("base64url");
  const jwt = `header.${payload}.signature`;
  assert.throws(() => extractExpClaim(jwt), /missing numeric exp claim/);
});
