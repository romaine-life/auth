// Verify an auth.romaine.life-signed bearer JWT for the admin surface.
//
// The /admin/* endpoints (src/server.ts) historically required a Better
// Auth browser session. mcp-auth — which forwards the caller's JWT to
// auth.romaine.life's admin endpoints — and a direct authromaine bot token
// have no such session, so they need a JWT path. This is that path: verify
// the token against our own JWKS (the RS256 keys /api/auth/jwks publishes)
// and require role=admin.
//
// I/O is injected: the caller supplies the key set (server.ts passes
// auth.api.getJwks(); tests pass a fixture), keeping this module pure and
// unit-testable. Contract mirrors the romaine-auth-py verifier: issuer is
// pinned; audience is intentionally NOT pinned because every
// auth.romaine.life token carries aud=issuer, which provides no per-app
// isolation.

import { jwtVerify, createLocalJWKSet, type JWTPayload, type JSONWebKeySet } from "jose";

export const DEFAULT_ADMIN_BEARER_ISSUER = "https://auth.romaine.life";

/** Verify `token` against `jwks` and require a role=admin claim.
 *
 *  Resolves to the verified JWT payload (sub/email/name/role/purpose) on
 *  success. Rejects — via jose or an explicit throw — on a bad signature,
 *  an expired/not-yet-valid token, an issuer mismatch, or any role other
 *  than admin. Callers treat any rejection as "not an admin." */
export async function verifyAdminBearerJwt(
  token: string,
  jwks: JSONWebKeySet,
  issuer: string = DEFAULT_ADMIN_BEARER_ISSUER,
): Promise<JWTPayload> {
  const keySet = createLocalJWKSet(jwks);
  const { payload } = await jwtVerify(token, keySet, { issuer });
  const role = typeof payload.role === "string" ? payload.role : "user";
  if (role !== "admin") {
    throw new Error(`token role is ${JSON.stringify(role)}, not admin`);
  }
  return payload;
}
