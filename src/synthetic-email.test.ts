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
