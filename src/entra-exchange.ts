// Microsoft Entra ID access token → auth.romaine.life user JWT exchange.
//
// Lets a CLI caller exchange the access token sitting in their `az` session
// for a human-shaped auth.romaine.life JWT, skipping the interactive
// browser sign-in. The minted JWT is indistinguishable from one produced
// via the cookie path (`/api/auth/token`): same iss, aud, signing key,
// claim shape — so downstream apps (tank-operator, glimmung, etc.) verify
// it through their existing JWKS-backed validators with no changes.
//
// Tightening rules:
//   1. The Entra app registration is pinned via ENTRA_EXCHANGE_AUDIENCE
//      and ENTRA_EXCHANGE_TENANT_ID. A token issued for any other resource
//      or tenant is rejected at the verifier — see src/entra-auth.ts.
//   2. The user must already exist in the Better Auth user table. We do
//      NOT auto-create on first exchange: silently provisioning users
//      from any tenant the audience pins to would widen the surface from
//      "anyone in tenant X with role admin/user can act" to "anyone in
//      tenant X gets a pending account, awaiting promotion." The
//      interactive Microsoft sign-in at auth.romaine.life is the only
//      way to enter the user table.
//   3. Only role ∈ {admin, user} is accepted. role=pending (default for
//      fresh sign-ups) and role=service (synthetic accounts only) are
//      rejected with their own telemetry reasons.
//
// Parallel to src/service-exchange.ts. Both end in `auth.api.signJWT`.

import { eq, sql } from "drizzle-orm";
import { auth } from "./auth.js";
import { db } from "./db/client.js";
import { user } from "./db/schema.js";
import { verifyEntraToken } from "./entra-auth.js";
import {
  EntraExchangeError,
  extractExpClaim,
  pickEntraEmail,
} from "./entra-exchange-helpers.js";

/** Roles accepted for human users on the exchange path. `pending` (default
 *  on fresh sign-up) and `service` (synthetic SA-exchange accounts) are
 *  rejected so a misconfigured row never produces a usable JWT. Keep in
 *  sync with the gate in tank-operator's auth.ExchangeRomaineLifeToken. */
const ACCEPTED_ROLES = new Set(["admin", "user"]);

function getAudience(): string {
  return (process.env.ENTRA_EXCHANGE_AUDIENCE ?? "").trim();
}

function getTenantId(): string {
  return (process.env.ENTRA_EXCHANGE_TENANT_ID ?? "").trim();
}

export interface EntraExchangeResult {
  token: string;
  userId: string;
  email: string;
  /** Seconds-since-epoch when the JWT expires. Mirrors the JWT's `exp`
   *  claim; surfaced so callers (the tank-jwt-from-az shim) can cache
   *  with a TTL check without re-parsing the JWT. Default 15 min per
   *  Better Auth's expirationTime — matches the cookie-path JWT exactly. */
  expiresAt: number;
}

/**
 * Exchange a verified Entra access token for an auth.romaine.life user
 * JWT. Throws `EntraExchangeError` on any failure with a stable telemetry
 * reason and the appropriate HTTP status for the route handler to surface.
 */
export async function exchangeEntraToken(
  accessToken: string,
): Promise<EntraExchangeResult> {
  if (!accessToken || accessToken.trim().length === 0) {
    throw new EntraExchangeError("missing access_token", 400, "missing_token");
  }

  // 1. Verify signature, issuer, audience, tenant, expiry.
  const verified = await verifyEntraToken(accessToken.trim(), {
    tenantId: getTenantId(),
    audience: getAudience(),
  });

  // 2. Resolve a usable email from the token's claims. Entra's email
  //    surfaces under different claim names depending on token version
  //    and account type; pickEntraEmail tries the documented set.
  const email = pickEntraEmail(verified.claims);
  if (!email) {
    throw new EntraExchangeError(
      "token has no email/upn/preferred_username claim; cannot map to a Better Auth user",
      401,
      "missing_email_claim",
    );
  }

  // 3. Find the Better Auth user. Case-insensitive on email because
  //    Microsoft normalizes work UPNs to lowercase but personal accounts
  //    sometimes round-trip mixed-case. Better Auth's signup flow stores
  //    whatever the OAuth provider returned, so we can't assume normalized.
  //    No auto-create — see the "tightening rules" comment at the top.
  let rows;
  try {
    rows = await db
      .select({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        apps: user.apps,
      })
      .from(user)
      .where(sql`lower(${user.email}) = ${email.toLowerCase()}`)
      .limit(1);
  } catch (e) {
    throw new EntraExchangeError(
      `user lookup failed: ${(e as Error).message}`,
      500,
      "error_internal",
    );
  }

  const row = rows[0];
  if (!row) {
    throw new EntraExchangeError(
      `no Better Auth user for ${email}; sign in interactively at auth.romaine.life first`,
      404,
      "unknown_user",
    );
  }

  if (!ACCEPTED_ROLES.has(row.role)) {
    throw new EntraExchangeError(
      `user ${email} has role ${row.role}; only admin/user can exchange`,
      403,
      "role_pending",
    );
  }

  // 4. Parse the per-user `apps` blob exactly the way the cookie-path
  //    JWT does in auth.ts → definePayload. A malformed JSON shouldn't
  //    block the exchange — silently default to {} like definePayload.
  let apps: Record<string, unknown> = {};
  try {
    apps = JSON.parse(row.apps ?? "{}");
  } catch {
    apps = {};
  }

  // 5. Mint. Better Auth's signJWT defaults `iss`/`aud` to BASE_URL
  //    (https://auth.romaine.life) and `exp` to 15 minutes — matches the
  //    cookie-path JWT exactly, so the same downstream JWKS-backed
  //    verifiers accept either without code changes.
  let signed;
  try {
    signed = await auth.api.signJWT({
      body: {
        payload: {
          sub: row.id,
          email: row.email,
          name: row.name,
          role: row.role,
          apps,
        },
      },
    });
  } catch (e) {
    throw new EntraExchangeError(
      `signJWT failed: ${(e as Error).message}`,
      500,
      "error_jwt_mint",
    );
  }

  // Bump updatedAt so the admin console reflects recent activity — the
  // same touch the cookie path applies via Better Auth's session refresh.
  // Best-effort; a failure here doesn't invalidate the JWT we already minted.
  try {
    await db
      .update(user)
      .set({ updatedAt: new Date() })
      .where(eq(user.id, row.id));
  } catch {
    // Ignore — the JWT is the load-bearing output.
  }

  return {
    token: signed.token,
    userId: row.id,
    email: row.email,
    expiresAt: extractExpClaim(signed.token),
  };
}
