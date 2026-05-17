import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  type JWK,
  type KeyLike,
} from "jose";
import {
  _resetEntraAuthCache,
  verifyEntraToken,
} from "./entra-auth.js";
import { EntraExchangeError } from "./entra-exchange-helpers.js";

// End-to-end coverage of the Entra-token verifier against a localhost
// JWKS fixture. The verifier is thin (jose does the cryptography) but the
// glue around it carries real failure modes:
//   - jose error-code → telemetry reason mapping
//   - tid claim mismatch (defense-in-depth past the iss check)
//   - oid/tid extraction with a defensive null guard
//   - acceptance of both v1 (sts.windows.net) and v2 (login.microsoftonline.com)
//     issuer formats since `az` tokens are v1 by default
// All of these are easy to regress silently if the verifier is later
// refactored, so they're worth real fixture tests rather than mocked jose.

const TENANT_ID = "2236b5e4-81d2-4d82-bde5-17b1037999ea";
const AUDIENCE = "api://test-app-1234";
const KID_GOOD = "test-key-good";
const KID_OTHER = "test-key-other";

let signingKey: KeyLike;
let signingPublicJwk: JWK;
let otherKey: KeyLike; // a second keypair so we can test wrong-sig
let server: http.Server;
let serverBase: string;

before(async () => {
  const good = await generateKeyPair("RS256");
  const other = await generateKeyPair("RS256");
  signingKey = good.privateKey;
  otherKey = other.privateKey;
  signingPublicJwk = { ...(await exportJWK(good.publicKey)), kid: KID_GOOD, alg: "RS256", use: "sig" };
  const otherPublicJwk: JWK = { ...(await exportJWK(other.publicKey)), kid: KID_OTHER, alg: "RS256", use: "sig" };

  // Mini Entra-shaped discovery + JWKS surface. Only the routes the
  // verifier touches; anything else returns 404 so a typo in the verifier
  // surfaces as a fetch failure rather than a silent skip.
  server = http.createServer((req, res) => {
    if (req.url === `/${TENANT_ID}/v2.0/.well-known/openid-configuration`) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jwks_uri: `${serverBase}/jwks` }));
      return;
    }
    if (req.url === "/jwks") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [signingPublicJwk, otherPublicJwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  serverBase = `http://127.0.0.1:${port}`;
  process.env.ENTRA_AUTHORITY_HOST = serverBase;
});

after(() => {
  server?.close();
  delete process.env.ENTRA_AUTHORITY_HOST;
  _resetEntraAuthCache();
});

beforeEach(() => {
  // Verifier caches JWKS by tenant; reset between tests so issuer/audience
  // overrides don't leak across cases.
  _resetEntraAuthCache();
});

interface ClaimOverrides {
  issuer?: string;
  audience?: string;
  tid?: string;
  oid?: string | null;
  exp?: number;
  iat?: number;
  email?: string;
  signingKey?: KeyLike;
  kid?: string;
}

async function signTestToken(overrides: ClaimOverrides = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    tid: overrides.tid ?? TENANT_ID,
    iat: overrides.iat ?? now,
    email: overrides.email ?? "nelson-devops-project@outlook.com",
  };
  // oid omitted only when explicitly set to null (testing the missing-claim
  // path). Default to a stable test value.
  if (overrides.oid !== null) {
    payload["oid"] = overrides.oid ?? "00000000-0000-0000-0000-000000000001";
  }
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: overrides.kid ?? KID_GOOD })
    .setIssuer(overrides.issuer ?? `${serverBase}/${TENANT_ID}/v2.0`)
    .setAudience(overrides.audience ?? AUDIENCE)
    .setExpirationTime(overrides.exp ?? now + 3600)
    .sign(overrides.signingKey ?? signingKey);
}

test("verifyEntraToken: happy path returns oid + tid + claims", async () => {
  const token = await signTestToken();
  const verified = await verifyEntraToken(token, {
    tenantId: TENANT_ID,
    audience: AUDIENCE,
  });
  assert.strictEqual(verified.oid, "00000000-0000-0000-0000-000000000001");
  assert.strictEqual(verified.tid, TENANT_ID);
  assert.strictEqual(verified.claims["email"], "nelson-devops-project@outlook.com");
});

test("verifyEntraToken: accepts v1 issuer (sts.windows.net) for the configured tenant", async () => {
  // az CLI tokens are v1 by default unless the app manifest opts into v2.
  // The verifier must accept both issuer shapes for the same tenant.
  const token = await signTestToken({
    issuer: `https://sts.windows.net/${TENANT_ID}/`,
  });
  const verified = await verifyEntraToken(token, {
    tenantId: TENANT_ID,
    audience: AUDIENCE,
  });
  assert.strictEqual(verified.tid, TENANT_ID);
});

test("verifyEntraToken: rejects expired token with token_expired", async () => {
  const now = Math.floor(Date.now() / 1000);
  const token = await signTestToken({ exp: now - 60, iat: now - 120 });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "token_expired" && e.status === 401,
  );
});

test("verifyEntraToken: rejects wrong audience with invalid_audience", async () => {
  const token = await signTestToken({ audience: "api://some-other-app" });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "invalid_audience" && e.status === 401,
  );
});

test("verifyEntraToken: rejects wrong issuer with invalid_issuer", async () => {
  const token = await signTestToken({ issuer: "https://attacker.example/" });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "invalid_issuer" && e.status === 401,
  );
});

test("verifyEntraToken: rejects token signed by an unrelated key with invalid_signature", async () => {
  // Sign with `otherKey` but advertise `kid: KID_GOOD` in the header — the
  // JWKS lookup finds the good key but verification fails.
  const token = await signTestToken({ signingKey: otherKey });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "invalid_signature" && e.status === 401,
  );
});

test("verifyEntraToken: rejects token with no matching JWKS kid as invalid_signature", async () => {
  const token = await signTestToken({ kid: "unknown-kid" });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "invalid_signature" && e.status === 401,
  );
});

test("verifyEntraToken: rejects token missing oid as invalid_signature (claim shape)", async () => {
  const token = await signTestToken({ oid: null });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError &&
      e.reason === "invalid_signature" &&
      /missing oid/i.test(e.message),
  );
});

test("verifyEntraToken: rejects token whose tid claim disagrees with configured tenant", async () => {
  // Defense in depth past the iss check: jose verifies iss against the
  // tenant URL, but the verifier also asserts tid matches. A token whose
  // tid disagrees with config is rejected even though iss was acceptable.
  const otherTenant = "11111111-1111-1111-1111-111111111111";
  const token = await signTestToken({ tid: otherTenant });
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "invalid_tenant" && e.status === 401,
  );
});

test("verifyEntraToken: rejects when ENTRA_EXCHANGE_TENANT_ID is empty (config_missing)", async () => {
  const token = await signTestToken();
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: "", audience: AUDIENCE }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "config_missing" && e.status === 503,
  );
});

test("verifyEntraToken: rejects when audience is empty (config_missing)", async () => {
  const token = await signTestToken();
  await assert.rejects(
    () => verifyEntraToken(token, { tenantId: TENANT_ID, audience: "" }),
    (e: unknown) =>
      e instanceof EntraExchangeError && e.reason === "config_missing" && e.status === 503,
  );
});
