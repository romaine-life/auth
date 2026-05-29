import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FEDERATION_MAX_TTL_SECONDS,
  validateFederationRequest,
} from "./federation-helpers.js";

// The orchestrator in src/federation-exchange.ts wires
// `validateFederationRequest` together with the SA verifier and the
// mint helper. The full chain (verify → audience gate → mint) needs a
// live cluster OIDC issuer + Better Auth signing key — exercised by
// glimmung's native-runner integration path.
//
// Unit coverage here pins the input-gate contract that the
// orchestrator depends on for its 4xx surface. The (status, reason)
// pairs returned here are exactly what the route handler in
// src/server.ts maps to JSON+HTTP status, so a drift in either side
// surfaces as a test failure.

const ALLOW = ["api.tailscale.com/*"];

test("missing audience → 400 denied_audience_missing", () => {
  const result = validateFederationRequest({ audience: "", audienceAllowlist: ALLOW });
  assert.ok(result);
  assert.strictEqual(result.status, 400);
  assert.strictEqual(result.reason, "denied_audience_missing");
});

test("whitespace-only audience → denied_audience_missing (trims before check)", () => {
  const result = validateFederationRequest({ audience: "   ", audienceAllowlist: ALLOW });
  assert.ok(result);
  assert.strictEqual(result.reason, "denied_audience_missing");
});

test("disallowed audience → 400 denied_audience_not_allowed", () => {
  const result = validateFederationRequest({
    audience: "https://other.example.com",
    audienceAllowlist: ALLOW,
  });
  assert.ok(result);
  assert.strictEqual(result.status, 400);
  assert.strictEqual(result.reason, "denied_audience_not_allowed");
});

test("empty allowlist refuses every audience (fail-closed)", () => {
  const result = validateFederationRequest({
    audience: "api.tailscale.com/anything",
    audienceAllowlist: [],
  });
  assert.ok(result);
  assert.strictEqual(result.reason, "denied_audience_not_allowed");
});

test("matching audience + no TTL → passes (returns null)", () => {
  assert.strictEqual(
    validateFederationRequest({
      audience: "api.tailscale.com/T6vFBk1dAa11CNTRL",
      audienceAllowlist: ALLOW,
    }),
    null,
  );
});

test("negative or zero TTL → 400 denied_ttl", () => {
  for (const ttl of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    const result = validateFederationRequest({
      audience: "api.tailscale.com/x",
      audienceAllowlist: ALLOW,
      ttlSeconds: ttl,
    });
    assert.ok(result, `should reject ttl=${ttl}`);
    assert.strictEqual(result.reason, "denied_ttl");
  }
});

test("ttl > FEDERATION_MAX_TTL_SECONDS → 400 denied_ttl", () => {
  const result = validateFederationRequest({
    audience: "api.tailscale.com/x",
    audienceAllowlist: ALLOW,
    ttlSeconds: FEDERATION_MAX_TTL_SECONDS + 1,
  });
  assert.ok(result);
  assert.strictEqual(result.reason, "denied_ttl");
});

test("ttl == FEDERATION_MAX_TTL_SECONDS is at the boundary and accepted", () => {
  assert.strictEqual(
    validateFederationRequest({
      audience: "api.tailscale.com/x",
      audienceAllowlist: ALLOW,
      ttlSeconds: FEDERATION_MAX_TTL_SECONDS,
    }),
    null,
  );
});
