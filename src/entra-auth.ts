// Microsoft Entra ID (AAD) JWT verifier. The companion to src/k8s-auth.ts:
// k8s-auth verifies cluster-issued SA tokens; this verifies Entra-issued
// user access tokens. Both use jose's createRemoteJWKSet + jwtVerify; what
// differs is the discovery URL, expected issuer, and the audience pin.
//
// Used by /api/auth/entra-exchange to authenticate a CLI caller via the
// access token sitting in their `az` session, mapping it to a Better
// Auth user and minting an auth.romaine.life JWT. The Entra app
// registration (audience) and the home tenant are pinned via env so a
// token issued for any other Entra resource cannot be replayed here.

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { EntraExchangeError } from "./entra-exchange-helpers.js";

const DEFAULT_ENTRA_AUTHORITY_HOST = "https://login.microsoftonline.com";

/** Authority host the verifier discovers the tenant's JWKS from. Production
 *  always uses Microsoft's `login.microsoftonline.com`; ENTRA_AUTHORITY_HOST
 *  override exists so tests can point the verifier at a localhost fixture
 *  server without monkey-patching jose. Resolved per-call (not cached) so
 *  a test can `_resetEntraAuthCache()` between cases. */
function authorityHost(): string {
  return (process.env.ENTRA_AUTHORITY_HOST ?? DEFAULT_ENTRA_AUTHORITY_HOST).replace(/\/$/, "");
}

let jwksGetter: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksTenantId: string | null = null;
let jwksInitError: Error | null = null;
let jwksInitPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;

/** Resolve the tenant's JWKS via OIDC discovery and cache it for the lifetime
 *  of the process. Microsoft serves the discovery doc at the v2.0 path; the
 *  JWKS it points to verifies both v1 and v2 access tokens (same signing
 *  keys), so we don't need to pick a token-version branch here. The remote
 *  JWKS getter handles per-kid caching with its own internal TTL, so key
 *  rotation works without a process restart. */
async function getEntraJwks(
  tenantId: string,
): Promise<ReturnType<typeof createRemoteJWKSet>> {
  // Tenant should not change at runtime, but guard anyway — a re-read of
  // env after rotation would otherwise silently keep verifying against the
  // old tenant's keys.
  if (jwksGetter && jwksTenantId === tenantId) return jwksGetter;
  if (jwksInitError && jwksTenantId === tenantId) throw jwksInitError;
  if (jwksInitPromise && jwksTenantId === tenantId) return jwksInitPromise;
  jwksTenantId = tenantId;
  jwksInitPromise = (async () => {
    const discoUrl = `${authorityHost()}/${tenantId}/v2.0/.well-known/openid-configuration`;
    const res = await fetch(discoUrl);
    if (!res.ok) {
      throw new Error(`Entra discovery failed: ${discoUrl} → HTTP ${res.status}`);
    }
    const doc = (await res.json()) as { jwks_uri?: string };
    if (!doc.jwks_uri) {
      throw new Error(`Entra discovery doc missing jwks_uri: ${discoUrl}`);
    }
    const getter = createRemoteJWKSet(new URL(doc.jwks_uri));
    jwksGetter = getter;
    return getter;
  })();
  try {
    return await jwksInitPromise;
  } catch (e) {
    jwksInitError = e instanceof Error ? e : new Error(String(e));
    jwksInitPromise = null;
    throw jwksInitError;
  }
}

/** Acceptable issuers for an Entra access token for the configured tenant.
 *  Entra ID issues v1 and v2 tokens with different `iss` formats; an `az`
 *  CLI token is v1 by default (`sts.windows.net`) but apps whose manifest
 *  sets `accessTokenAcceptedVersion: 2` get v2 tokens (`login.microsoftonline.com/.../v2.0`).
 *  We accept both so the operator doesn't have to know which version their
 *  app produces. The audience pin is the load-bearing safeguard against
 *  cross-resource replay; the issuer check just enforces "minted by the
 *  expected tenant." */
function acceptableIssuers(tenantId: string): string[] {
  return [
    `${authorityHost()}/${tenantId}/v2.0`,
    `https://sts.windows.net/${tenantId}/`,
  ];
}

export interface EntraVerifyOptions {
  /** The tenant id (GUID) the inbound token must have been issued by. The
   *  `tid` claim must match this exactly. */
  tenantId: string;
  /** The audience claim the inbound token must carry. Pin to the Entra app
   *  registration's `api://<appId>` identifier URI (or its raw client id —
   *  both forms are accepted by jose as long as the token's `aud` matches
   *  one of the configured values). No default; misconfiguration must fail
   *  closed rather than accept any audience. */
  audience: string | string[];
}

export interface VerifiedEntraToken {
  /** Stable Entra user id, scoped to the tenant. Use as a Better Auth
   *  account identifier if we ever wire OID-based identity linking. */
  oid: string;
  /** The tenant id the token was issued by. Caller has already pinned
   *  this against config, but returning it lets the audit log carry the
   *  observed value rather than the expected. */
  tid: string;
  /** Best-effort email pulled from the token. May be email/upn/preferred_username
   *  depending on the token version + account type — caller resolves
   *  via pickEntraEmail. */
  claims: JWTPayload & Record<string, unknown>;
}

/**
 * Verify an Entra ID access token. Returns the parsed claims plus the
 * resolved (oid, tid). Throws EntraExchangeError with a telemetry reason
 * on any failure so the route handler can record the outcome and return
 * the right HTTP status without parsing jose's error messages itself.
 */
export async function verifyEntraToken(
  token: string,
  options: EntraVerifyOptions,
): Promise<VerifiedEntraToken> {
  if (!options.tenantId) {
    throw new EntraExchangeError(
      "ENTRA_EXCHANGE_TENANT_ID is not configured",
      503,
      "config_missing",
    );
  }
  if (
    !options.audience ||
    (Array.isArray(options.audience) && options.audience.length === 0)
  ) {
    throw new EntraExchangeError(
      "ENTRA_EXCHANGE_AUDIENCE is not configured",
      503,
      "config_missing",
    );
  }

  let jwks: ReturnType<typeof createRemoteJWKSet>;
  try {
    jwks = await getEntraJwks(options.tenantId);
  } catch (e) {
    throw new EntraExchangeError(
      `Entra JWKS unavailable: ${(e as Error).message}`,
      503,
      "jwks_fetch_failed",
    );
  }

  const issuers = acceptableIssuers(options.tenantId);
  let payload: JWTPayload;
  try {
    const verified = await jwtVerify(token, jwks, {
      issuer: issuers,
      audience: options.audience,
    });
    payload = verified.payload;
  } catch (e) {
    // jose throws a small set of typed errors. The error `code` is the
    // load-bearing discriminator; messages are not stable. We map each
    // code to one of our telemetry reasons.
    const code = (e as { code?: string }).code ?? "";
    const message = (e as Error).message ?? "verification failed";
    switch (code) {
      case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
      case "ERR_JWS_INVALID":
      case "ERR_JWKS_NO_MATCHING_KEY":
        throw new EntraExchangeError(message, 401, "invalid_signature");
      case "ERR_JWT_CLAIM_VALIDATION_FAILED": {
        // jose attaches `claim` for claim-validation failures.
        const claim = (e as { claim?: string }).claim;
        if (claim === "iss") {
          throw new EntraExchangeError(message, 401, "invalid_issuer");
        }
        if (claim === "aud") {
          throw new EntraExchangeError(message, 401, "invalid_audience");
        }
        throw new EntraExchangeError(message, 401, "invalid_signature");
      }
      case "ERR_JWT_EXPIRED":
        throw new EntraExchangeError(message, 401, "token_expired");
      default:
        throw new EntraExchangeError(message, 401, "invalid_signature");
    }
  }

  const oid =
    typeof payload["oid"] === "string" ? (payload["oid"] as string) : null;
  const tid =
    typeof payload["tid"] === "string" ? (payload["tid"] as string) : null;
  if (!oid || !tid) {
    throw new EntraExchangeError(
      "token missing oid/tid claims",
      401,
      "invalid_signature",
    );
  }
  // Defense-in-depth: jose already enforced `iss` against the tenant URL,
  // but `tid` is the authoritative tenant claim on the token. A token
  // issued by a malicious authority that spoofs `iss` would still need to
  // match `tid` here, and would still fail signature verification — but
  // belt-and-suspenders is cheap for a security-critical gate.
  if (tid !== options.tenantId) {
    throw new EntraExchangeError(
      `token tid ${tid} does not match configured tenant`,
      401,
      "invalid_tenant",
    );
  }

  return {
    oid,
    tid,
    claims: payload as JWTPayload & Record<string, unknown>,
  };
}

/** Test-only: clear the cached JWKS getter so a test can re-init from env. */
export function _resetEntraAuthCache(): void {
  jwksGetter = null;
  jwksTenantId = null;
  jwksInitError = null;
  jwksInitPromise = null;
}
