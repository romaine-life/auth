import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RESERVED_SERVICE_EMAIL_DOMAINS,
  buildServiceEmail,
  buildServiceName,
  isReservedServiceEmail,
} from "./synthetic-email.js";

test("buildServiceEmail: builds the canonical pod-<id>@service.<consumer>.romaine.life shape", () => {
  assert.strictEqual(
    buildServiceEmail("tank", "abc123"),
    "pod-abc123@service.tank.romaine.life",
  );
});

test("buildServiceEmail: refuses unregistered consumers (forces RESERVED_SERVICE_EMAIL_DOMAINS update)", () => {
  assert.throws(
    () => buildServiceEmail("ambience", "abc"),
    /not in RESERVED_SERVICE_EMAIL_DOMAINS/,
  );
});

test("buildServiceEmail: refuses non-DNS-safe consumer values", () => {
  assert.throws(() => buildServiceEmail("Tank", "abc"), /consumer must be lowercase/);
  assert.throws(() => buildServiceEmail("ta nk", "abc"), /consumer must be lowercase/);
});

test("buildServiceEmail: refuses empty or whitespace identifiers", () => {
  assert.throws(() => buildServiceEmail("", "abc"), /consumer must be non-empty/);
  assert.throws(() => buildServiceEmail("tank", ""), /stableId must be non-empty/);
  assert.throws(() => buildServiceEmail("tank", "   "), /stableId must be non-empty/);
});

test("buildServiceEmail: refuses stableIds with @ or . that would break the email shape", () => {
  assert.throws(() => buildServiceEmail("tank", "a.b"), /stableId must be/);
  assert.throws(() => buildServiceEmail("tank", "a@b"), /stableId must be/);
});

test("isReservedServiceEmail: matches the canonical synthetic domain", () => {
  assert.strictEqual(isReservedServiceEmail("pod-xyz@service.tank.romaine.life"), true);
});

test("isReservedServiceEmail: case-insensitive on the domain", () => {
  assert.strictEqual(isReservedServiceEmail("pod-xyz@SERVICE.TANK.ROMAINE.LIFE"), true);
});

test("isReservedServiceEmail: rejects non-reserved domains (humans cannot squat the namespace)", () => {
  assert.strictEqual(isReservedServiceEmail("user@romaine.life"), false);
  assert.strictEqual(isReservedServiceEmail("user@tank.romaine.life"), false);
  assert.strictEqual(isReservedServiceEmail("user@example.com"), false);
});

test("isReservedServiceEmail: handles malformed inputs without throwing", () => {
  assert.strictEqual(isReservedServiceEmail("no-at-sign"), false);
  assert.strictEqual(isReservedServiceEmail(""), false);
});

test("buildServiceName: includes the consumer and stableId for admin-UI clarity", () => {
  assert.strictEqual(
    buildServiceName("tank", "abc"),
    "Service: tank pod-abc",
  );
});

test("RESERVED_SERVICE_EMAIL_DOMAINS contains the tank consumer (regression-guard against accidental removal)", () => {
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.tank.romaine.life"));
});

test("RESERVED_SERVICE_EMAIL_DOMAINS does NOT contain mcp-glimmung (deleted — mcp-glimmung forwards inbound JWTs and no longer mints its own)", () => {
  assert.ok(!RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.mcp-glimmung.romaine.life"));
});

test("RESERVED_SERVICE_EMAIL_DOMAINS contains the mcp-k8s / mcp-argocd / mcp-azure-personal consumers", () => {
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.mcp-k8s.romaine.life"));
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.mcp-argocd.romaine.life"));
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.mcp-azure-personal.romaine.life"));
});

test("RESERVED_SERVICE_EMAIL_DOMAINS contains the tank-operator orchestrator consumer (nelsong6/tank-operator#540 follow-up)", () => {
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.tank-operator.romaine.life"));
});

test("RESERVED_SERVICE_EMAIL_DOMAINS contains the glimmung orchestrator consumer", () => {
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.glimmung.romaine.life"));
});

test("RESERVED_SERVICE_EMAIL_DOMAINS keeps `tank` and `tank-operator` as distinct subdomains (leaked session JWT cannot be swapped for an orchestrator JWT)", () => {
  // Both must be present, and they must be distinct strings. Future
  // refactor that collapses them into one slug should delete this test
  // explicitly and document the rationale.
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.tank.romaine.life"));
  assert.ok(RESERVED_SERVICE_EMAIL_DOMAINS.includes("service.tank-operator.romaine.life"));
  assert.notStrictEqual("service.tank.romaine.life", "service.tank-operator.romaine.life");
});

test("buildServiceEmail: mints under each new pod-stable MCP consumer", () => {
  for (const slug of ["mcp-k8s", "mcp-argocd", "mcp-azure-personal"]) {
    assert.strictEqual(
      buildServiceEmail(slug, slug),
      `pod-${slug}@service.${slug}.romaine.life`,
    );
  }
});

test("buildServiceEmail: mints under the glimmung consumer (pod-stable singleton)", () => {
  assert.strictEqual(
    buildServiceEmail("glimmung", "glimmung"),
    "pod-glimmung@service.glimmung.romaine.life",
  );
});

test("buildServiceEmail: mints under the tank-operator orchestrator consumer", () => {
  assert.strictEqual(
    buildServiceEmail("tank-operator", "orchestrator"),
    "pod-orchestrator@service.tank-operator.romaine.life",
  );
});
