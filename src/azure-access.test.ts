import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AZURE_GRANT_DEFAULT_MINUTES,
  AZURE_GRANT_MAX_MINUTES,
  AZURE_TOKEN_TTL_SECONDS,
  AzureAccessError,
  azureTokenTtlSeconds,
  createDecisionSignal,
  effectiveStatus,
  machineFromClaims,
  parseAzureAccessRequest,
} from "./azure-access.js";
import { resolveAudience } from "./device-helpers.js";

test("a request needs a reason and takes a duration within bounds", () => {
  assert.deepEqual(parseAzureAccessRequest({ reason: "  read  the  cluster " }),
    { reason: "read the cluster", minutes: AZURE_GRANT_DEFAULT_MINUTES });
  assert.deepEqual(parseAzureAccessRequest({ reason: "x", minutes: 30 }), { reason: "x", minutes: 30 });
  for (const body of [{}, { reason: "   " }, { reason: "x", minutes: 5 }, { reason: "x", minutes: AZURE_GRANT_MAX_MINUTES + 1 },
    { reason: "x", minutes: 30.5 }, { reason: "x", minutes: "60" }, { reason: "x".repeat(501) }]) {
    assert.throws(() => parseAzureAccessRequest(body as Record<string, unknown>), AzureAccessError, JSON.stringify(body));
  }
});

test("a pending request past its deadline and an approved grant past its end read as expired", () => {
  const now = new Date("2026-11-24T12:00:00Z");
  const before = new Date(now.getTime() - 1000);
  const after = new Date(now.getTime() + 1000);
  assert.equal(effectiveStatus({ status: "pending", requestExpiresAt: after, grantExpiresAt: null }, now), "pending");
  assert.equal(effectiveStatus({ status: "pending", requestExpiresAt: before, grantExpiresAt: null }, now), "expired");
  assert.equal(effectiveStatus({ status: "approved", requestExpiresAt: before, grantExpiresAt: after }, now), "approved");
  assert.equal(effectiveStatus({ status: "approved", requestExpiresAt: before, grantExpiresAt: before }, now), "expired");
  assert.equal(effectiveStatus({ status: "revoked", requestExpiresAt: before, grantExpiresAt: after }, now), "revoked");
  assert.equal(effectiveStatus({ status: "denied", requestExpiresAt: after, grantExpiresAt: null }, now), "denied");
});

test("a token never outlives its grant", () => {
  const now = new Date("2026-11-24T12:00:00Z");
  assert.equal(azureTokenTtlSeconds(new Date(now.getTime() + 3600_000), now), AZURE_TOKEN_TTL_SECONDS);
  assert.equal(azureTokenTtlSeconds(new Date(now.getTime() + 120_000), now), 120);
  assert.ok(azureTokenTtlSeconds(new Date(now.getTime() - 1000), now) <= 0);
});

test("only a home machine's token identifies a machine", () => {
  const machine = { sub: "device:abc/nelsonlaptop", role: "service", purpose: "machine", device: "nelsonlaptop" };
  assert.deepEqual(machineFromClaims(machine), { subject: "device:abc/nelsonlaptop", device: "nelsonlaptop" });
  for (const claims of [
    { ...machine, role: "admin" },
    { ...machine, purpose: "bot" },
    { ...machine, sub: "svc:mcp:mcp" },
    { ...machine, device: undefined },
  ]) {
    assert.throws(() => machineFromClaims(claims), AzureAccessError);
  }
});

test("a device may ask for the azure audience", () => {
  assert.deepEqual(resolveAudience("azure"), { audience: "azure", ttlSeconds: 600 });
});

test("a held status request wakes when its request is decided, and ends on its own otherwise", async () => {
  const signal = createDecisionSignal();
  const started = Date.now();
  const woken = signal.wait("aza_1", 5000);
  setTimeout(() => signal.notify("aza_1"), 20);
  await woken;
  assert.ok(Date.now() - started < 1000, "the decision should end the wait at once");

  const t0 = Date.now();
  await signal.wait("aza_2", 30);
  assert.ok(Date.now() - t0 >= 25, "an undecided request waits out its time");
});
