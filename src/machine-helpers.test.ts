import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { machineIdentity, machineTokenInput, machineRequestHash, machineSshPrincipal } from "./machine-helpers.js";
import { buildAuthJwtPayload } from "./mint-jwt-helpers.js";
import { isReservedServiceEmail } from "./synthetic-email.js";
import { DEVICE_TOKEN_URL, verifyDeviceAssertion, createJtiStore } from "./device-helpers.js";

test("machine token remains its own account with no human privilege inheritance", () => {
  const identity = machineIdentity("owner", "nelsonpc");
  const payload = buildAuthJwtPayload(machineTokenInput("owner", "nelsonpc", { ssh: [] }), () => 1000);
  assert.equal(payload.sub, identity.id);
  assert.notEqual(payload.sub, "owner");
  assert.equal(payload.role, "service");
  assert.equal(payload.purpose, "machine");
  assert.equal(payload.actor_email, identity.email);
  assert.equal(payload.exp - payload.iat, 900);
  assert.ok(isReservedServiceEmail(identity.email));
  assert.notEqual(machineIdentity("owner", "mac").id, identity.id);
  assert.notEqual(machineIdentity("other-owner", "nelsonpc").email, identity.email);
});

test("SSH principal is authorized for the particular host and OS account", () => {
  const grants = { ssh: [{ target: "nelsonpc", user: "nelson" }] };
  assert.equal(machineSshPrincipal("machine", "nelsonpc", "nelson", grants), "machine@nelsonpc/nelson");
  assert.throws(() => machineSshPrincipal("machine", "mac", "nelson", grants));
  assert.throws(() => machineSshPrincipal("machine", "nelsonpc", "root", grants));
  assert.throws(() => machineSshPrincipal("machine", "nelsonpc\nother", "nelson", grants));
});

test("directory-account SSH logins retain their full name and exact grant", () => {
  const user = "nromai01@stellarus.com";
  const grants = { ssh: [{ target: "fl7vg4g5ww.local", user }] };
  assert.equal(machineSshPrincipal("device:owner/nelsonpc", "fl7vg4g5ww.local", user, grants),
    "device:owner/nelsonpc@fl7vg4g5ww.local/nromai01@stellarus.com");
  assert.throws(() => machineSshPrincipal("machine", "fl7vg4g5ww.local", "nromai01", grants));
  for (const bad of [user + "\n", "../" + user, user + '\"', user + ",root", "-root"]) {
    assert.throws(() => machineSshPrincipal("machine", "fl7vg4g5ww.local", bad,
      { ssh: [{ target: "fl7vg4g5ww.local", user: bad }] }));
  }
});

test("captured assertions cannot authorize another SSH key, target, or audience", async () => {
  const now = 1_800_000_000;
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const original = { audience: "ssh", public_key: "key-one", target: "nelsonpc", user: "nelson" };
  const token = await new SignJWT({ jti: "one", request_hash: machineRequestHash(original) })
    .setProtectedHeader({ alg: "ES256", kid: "dev_1" }).setIssuer("dev_1").setSubject("dev_1")
    .setAudience(DEVICE_TOKEN_URL).setIssuedAt(now).setExpirationTime(now + 120).sign(privateKey);
  const device = { id: "dev_1", userId: "owner", name: "mac", publicKeyJwk: await exportJWK(publicKey), revokedAt: null };
  for (const altered of [{ ...original, public_key: "attacker-key" }, { ...original, target: "mac" }, { audience: "machine" }]) {
    await assert.rejects(verifyDeviceAssertion(token, { findDevice: async () => device, claimJti: createJtiStore(() => now), now: () => now, requestHash: machineRequestHash(altered) }));
  }
  const deps = { findDevice: async () => device, claimJti: createJtiStore(() => now), now: () => now, requestHash: machineRequestHash(original) };
  assert.equal((await verifyDeviceAssertion(token, deps)).id, "dev_1");
  await assert.rejects(verifyDeviceAssertion(token, deps));
});
