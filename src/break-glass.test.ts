import { test } from "node:test";
import assert from "node:assert/strict";
import { AZURE_GRANT_DEFAULT_MINUTES, AzureAccessError } from "./azure-access.js";
import {
  BREAK_GLASS_AUDIENCE,
  BREAK_GLASS_TOKEN_TTL_SECONDS,
  breakGlassTokenTtlSeconds,
  parseBreakGlassRequest,
} from "./break-glass.js";
import { resolveAudience } from "./device-helpers.js";

const SESSION = "0f8e2c1a-5b7d-4e2f-9a31-6c4d8b2e7f10";

test("a request names its session, with Azure access's reason and duration rules", () => {
  assert.deepEqual(parseBreakGlassRequest({ reason: " move  the runner keys ", session: ` ${SESSION} ` }),
    { reason: "move the runner keys", minutes: AZURE_GRANT_DEFAULT_MINUTES, session: SESSION });
  assert.deepEqual(parseBreakGlassRequest({ reason: "x", minutes: 15, session: SESSION }), { reason: "x", minutes: 15, session: SESSION });
  for (const body of [
    { reason: "x" },
    { reason: "x", session: "  " },
    { reason: "x", session: 42 },
    { reason: "x", session: "a b" },
    { reason: "x", session: "<script>" },
    { reason: "x", session: "a".repeat(129) },
    { session: SESSION },
    { reason: "x", session: SESSION, minutes: 14 },
    { reason: "x", session: SESSION, minutes: 481 },
  ]) {
    assert.throws(() => parseBreakGlassRequest(body as Record<string, unknown>), AzureAccessError, JSON.stringify(body));
  }
});

test("a cluster token never outlives its grant", () => {
  const now = new Date("2026-11-26T12:00:00Z");
  assert.equal(breakGlassTokenTtlSeconds(new Date(now.getTime() + 3600_000), now), BREAK_GLASS_TOKEN_TTL_SECONDS);
  assert.equal(BREAK_GLASS_TOKEN_TTL_SECONDS, 600);
  assert.equal(breakGlassTokenTtlSeconds(new Date(now.getTime() + 90_000), now), 90);
  assert.ok(breakGlassTokenTtlSeconds(new Date(now.getTime() - 1000), now) <= 0);
});

test("a device may ask for the home cluster's break-glass audience", () => {
  assert.equal(BREAK_GLASS_AUDIENCE, "home-cluster-break-glass");
  assert.deepEqual(resolveAudience("home-cluster-break-glass"), { audience: "home-cluster-break-glass", ttlSeconds: 600 });
});
