import { test } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import {
  ASSERTION_MAX_LIFETIME_SECONDS,
  DEVICE_TOKEN_URL,
  DeviceError,
  checkEnrollToken,
  createJtiStore,
  deviceSubject,
  parseEnrollRequest,
  resolveAudience,
  verifyDeviceAssertion,
  type StoredDevice,
} from "./device-helpers.js";

const NOW = 1_800_000_000;

async function fixture(revoked = false) {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk = (await exportJWK(publicKey)) as JWK;
  const device: StoredDevice = { id: "dev_1", userId: "u_1", name: "treadmill", publicKeyJwk: jwk, revokedAt: revoked ? new Date() : null };
  const sign = (claims: Record<string, unknown> = {}, opts: { kid?: string; iat?: number; exp?: number; aud?: string } = {}) =>
    new SignJWT({ jti: crypto.randomUUID(), ...claims })
      .setProtectedHeader({ alg: "ES256", kid: opts.kid ?? device.id })
      .setIssuer(device.id)
      .setSubject(device.id)
      .setAudience(opts.aud ?? DEVICE_TOKEN_URL)
      .setIssuedAt(opts.iat ?? NOW)
      .setExpirationTime(opts.exp ?? NOW + 60)
      .sign(privateKey);
  const deps = {
    findDevice: async (id: string) => (id === device.id ? device : null),
    claimJti: createJtiStore(() => NOW),
    now: () => NOW,
  };
  return { device, sign, deps, privateKey };
}

async function rejects(p: Promise<unknown>, reason: string) {
  await assert.rejects(p, (e: unknown) => e instanceof DeviceError && e.reason === reason);
}

test("a fresh assertion from a registered device verifies", async () => {
  const { sign, deps, device } = await fixture();
  assert.equal((await verifyDeviceAssertion(await sign(), deps)).id, device.id);
});

test("an unknown device is device_not_registered, a revoked one device_revoked", async () => {
  const f = await fixture();
  await rejects(verifyDeviceAssertion(await f.sign({}, { kid: "dev_other" }), f.deps), "device_not_registered");
  const r = await fixture(true);
  await rejects(verifyDeviceAssertion(await r.sign(), r.deps), "device_revoked");
});

test("an assertion signed by another key is refused", async () => {
  const f = await fixture();
  const other = await fixture();
  // Signed by `other`'s key but naming f's device.
  await rejects(verifyDeviceAssertion(await other.sign({}, { kid: f.device.id }), f.deps), "invalid_assertion");
});

test("a replayed assertion is refused", async () => {
  const { sign, deps } = await fixture();
  const a = await sign();
  await verifyDeviceAssertion(a, deps);
  await rejects(verifyDeviceAssertion(a, deps), "assertion_replayed");
});

test("wrong audience, expired, or too long-lived assertions are refused", async () => {
  const { sign, deps } = await fixture();
  await rejects(verifyDeviceAssertion(await sign({}, { aud: "https://elsewhere" }), deps), "invalid_assertion");
  await rejects(verifyDeviceAssertion(await sign({}, { iat: NOW - 600, exp: NOW - 300 }), deps), "invalid_assertion");
  await rejects(
    verifyDeviceAssertion(await sign({}, { iat: NOW, exp: NOW + ASSERTION_MAX_LIFETIME_SECONDS + 60 }), deps),
    "invalid_assertion",
  );
});

test("enroll takes only an EC P-256 public key", () => {
  const ok = parseEnrollRequest({ name: "treadmill", public_key_jwk: { kty: "EC", crv: "P-256", x: "a", y: "b" } });
  assert.deepEqual(ok.publicKeyJwk, { kty: "EC", crv: "P-256", x: "a", y: "b" });
  assert.throws(() => parseEnrollRequest({ name: "treadmill", public_key_jwk: { kty: "EC", crv: "P-256", x: "a", y: "b", d: "secret" } }));
  assert.throws(() => parseEnrollRequest({ name: "treadmill", public_key_jwk: { kty: "RSA", n: "a", e: "AQAB" } }));
  assert.throws(() => parseEnrollRequest({ name: "Tread Mill", public_key_jwk: { kty: "EC", crv: "P-256", x: "a", y: "b" } }));
});

test("enroll needs a recent human sign-in, not a device's or a bot's token", () => {
  assert.equal(checkEnrollToken({ role: "admin", iat: NOW - 60 }, NOW), null);
  assert.ok(checkEnrollToken({ role: "admin", iat: NOW - 3600 }, NOW));
  assert.ok(checkEnrollToken({ role: "admin", iat: NOW, device: "treadmill" }, NOW));
  assert.ok(checkEnrollToken({ role: "admin", iat: NOW, purpose: "bot" }, NOW));
  assert.ok(checkEnrollToken({ role: "service", iat: NOW }, NOW));
  assert.ok(checkEnrollToken({ role: "pending", iat: NOW }, NOW));
});

test("only declared audiences, and the subject names the user and the device", () => {
  assert.equal(resolveAudience(undefined), null);
  assert.deepEqual(resolveAudience("ssh"), { audience: "ssh", ttlSeconds: 600 });
  assert.throws(() => resolveAudience("openbao"));
  assert.throws(() => resolveAudience("toString"));
  assert.throws(() => resolveAudience("https://api.github.com"));
  assert.equal(deviceSubject("u_1", "treadmill"), "device:u_1/treadmill");
});
