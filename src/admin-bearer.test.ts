import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet, type KeyLike } from "jose";
import { verifyAdminBearerJwt } from "./admin-bearer.js";

// Verifies the admin bearer-token contract that lets mcp-auth (forwarding a
// caller's JWT) and a direct authromaine bot token reach the /admin surface
// without a browser session: signature against our JWKS, issuer pinned,
// role=admin required, expiry honored.

const ISSUER = "https://auth.romaine.life";

// One RS256 keypair stands in for the JWKS the jwt plugin publishes. The
// public half goes into the key set verifyAdminBearerJwt is given; the
// private half signs the test tokens.
const { publicKey, privateKey } = await generateKeyPair("RS256");
const publicJwk = await exportJWK(publicKey);
publicJwk.kid = "test-key-1";
publicJwk.alg = "RS256";
publicJwk.use = "sig";
const JWKS: JSONWebKeySet = { keys: [publicJwk] };

// A second, unrelated keypair — tokens it signs must NOT verify against JWKS.
const other = await generateKeyPair("RS256");

function mint(opts: {
  role?: string;
  issuer?: string;
  expiresIn?: string;
  signWith?: KeyLike | Uint8Array;
  email?: string;
}) {
  const jwt = new SignJWT({ role: opts.role ?? "admin", email: opts.email ?? "a@b.com" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
    .setIssuer(opts.issuer ?? ISSUER)
    .setSubject("user-123")
    .setIssuedAt()
    .setExpirationTime(opts.expiresIn ?? "1h");
  return jwt.sign(opts.signWith ?? privateKey);
}

test("accepts a valid role=admin token and returns its claims", async () => {
  const token = await mint({ role: "admin", email: "admin@romaine.life" });
  const payload = await verifyAdminBearerJwt(token, JWKS, ISSUER);
  assert.equal(payload.role, "admin");
  assert.equal(payload.email, "admin@romaine.life");
  assert.equal(payload.sub, "user-123");
});

test("rejects a role=user token", async () => {
  const token = await mint({ role: "user" });
  await assert.rejects(() => verifyAdminBearerJwt(token, JWKS, ISSUER), /not admin/);
});

test("rejects a token with no role claim (defaults to user)", async () => {
  const token = await new SignJWT({ email: "x@y.com" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
    .setIssuer(ISSUER)
    .setSubject("user-123")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
  await assert.rejects(() => verifyAdminBearerJwt(token, JWKS, ISSUER), /not admin/);
});

test("rejects a token signed by a key not in the JWKS", async () => {
  const token = await mint({ role: "admin", signWith: other.privateKey });
  await assert.rejects(() => verifyAdminBearerJwt(token, JWKS, ISSUER));
});

test("rejects a token from the wrong issuer", async () => {
  const token = await mint({ role: "admin", issuer: "https://evil.example.com" });
  await assert.rejects(() => verifyAdminBearerJwt(token, JWKS, ISSUER));
});

test("rejects an expired token", async () => {
  const token = await mint({ role: "admin", expiresIn: "-1m" });
  await assert.rejects(() => verifyAdminBearerJwt(token, JWKS, ISSUER));
});
