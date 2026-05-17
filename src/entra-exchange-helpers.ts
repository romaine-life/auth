// Pure helpers used by the Entra-token exchange orchestrator. Split out so
// they can be unit-tested without importing the DB client, Better Auth, or
// the JWKS getter (all of which require runtime env at module init).
//
// Parallel to src/service-exchange-helpers.ts (the k8s SA exchange path).
// Two exchange surfaces with the same shape:
//   - /api/auth/exchange/k8s   — projected pod SA token → service-principal JWT
//   - /api/auth/entra-exchange — Entra ID access token → human-user JWT
// Both end at `auth.api.signJWT`; the front-end is the only thing that
// differs.

/** Telemetry-grade reason for an Entra-exchange failure. Stable string set —
 *  if you add a value here, also extend EntraExchangeResultLabel in
 *  src/metrics.ts and the dashboard panel that reads the counter. */
export type EntraExchangeFailureReason =
  | "missing_token" // empty body / missing access_token
  | "invalid_signature" // jose: signature didn't verify against tenant JWKS
  | "invalid_issuer" // jose: iss doesn't match expected tenant issuer
  | "invalid_audience" // jose: aud doesn't match ENTRA_EXCHANGE_AUDIENCE
  | "invalid_tenant" // tid claim ≠ ENTRA_EXCHANGE_TENANT_ID
  | "token_expired" // jose: exp in past (or nbf in future)
  | "missing_email_claim" // no email/upn/preferred_username on the token
  | "unknown_user" // no Better Auth user matches the email
  | "role_pending" // user exists but role=pending (or unrecognized role)
  | "jwks_fetch_failed" // OIDC discovery or JWKS endpoint unreachable
  | "config_missing" // ENTRA_EXCHANGE_AUDIENCE / ENTRA_EXCHANGE_TENANT_ID unset
  | "error_jwt_mint" // Better Auth signJWT threw
  | "error_internal"; // anything else (DB unreachable, etc.)

export class EntraExchangeError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly reason: EntraExchangeFailureReason,
  ) {
    super(message);
    this.name = "EntraExchangeError";
  }
}

/** Pick a usable email from the verified Entra JWT claims. Entra tokens
 *  don't carry a single canonical email field — preferences vary by token
 *  version, account type (work/school vs personal), and how the app is
 *  registered. We try the documented Microsoft order:
 *    1. `email`          — present on v2 tokens for work/school accounts
 *                          that have an email-shaped UPN.
 *    2. `preferred_username` — UPN-shaped for work accounts, login name
 *                          for personal accounts. Usually email-shaped.
 *    3. `upn`            — v1-token field, still emitted for AAD users.
 *  Returns null if none parse as a non-empty string. The caller maps null
 *  to `missing_email_claim` so the rejection reason is telemetry-clean. */
export function pickEntraEmail(
  claims: Record<string, unknown>,
): string | null {
  const candidates = ["email", "preferred_username", "upn"] as const;
  for (const key of candidates) {
    const value = claims[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}

/** Decode the `exp` claim from a compact JWS. Copy of the helper in
 *  src/service-exchange-helpers.ts — duplicating one line rather than
 *  taking a dependency between the two exchange paths so either can be
 *  retired independently. */
export function extractExpClaim(jwt: string): number {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const payloadJson = Buffer.from(parts[1], "base64url").toString("utf8");
  const payload = JSON.parse(payloadJson) as { exp?: number };
  if (typeof payload.exp !== "number") {
    throw new Error("JWT payload missing numeric exp claim");
  }
  return payload.exp;
}
