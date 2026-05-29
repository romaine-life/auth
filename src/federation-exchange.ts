// k8s SA-token → external-audience federation JWT exchange.
//
// Inbound: a workload (today: glimmung's native-runner pod) presents its
// projected k8s ServiceAccount token and asks for a JWT scoped to a
// specific external audience (today: Tailscale's tailnet identifier).
// Outbound: a short-lived auth.romaine.life-signed JWT with iss/aud/sub
// that the third-party IdP can verify against /api/auth/jwks via
// /.well-known/openid-configuration discovery (RFC 7523 client_assertion
// flow).
//
// Why this is structurally separate from src/service-exchange.ts:
//   - Different inbound allowlist (K8S_FEDERATION_SA_ALLOWLIST vs
//     K8S_SERVICE_SA_ALLOWLIST). A workload trusted to act as a
//     service principal inside romaine.life is NOT the same trust
//     decision as a workload trusted to assert identity to an external
//     IdP. Conflating those allowlists would mean every existing
//     service-exchange caller silently gains external-audience
//     minting power on the day this lands.
//   - Different output shape — no `role`, no `actor_email`, no
//     synthetic-email user upsert. See src/mint-jwt.ts header.
//   - Different audience contract — service-exchange pins
//     `iss=aud=https://auth.romaine.life` to satisfy the platform
//     verifier; federation tokens carry an external audience that the
//     romaine.life verifier would (correctly) reject.

import { parseAllowlist, verifyK8sSAToken } from "./k8s-auth.js";
import {
  federationSubject,
  parseAudienceAllowlist,
  validateFederationRequest,
  FEDERATION_DEFAULT_TTL_SECONDS,
} from "./federation-helpers.js";
import { mintFederationJwt } from "./mint-jwt.js";

/** Audience pinned on inbound SA tokens. Mirrors the service-exchange
 *  pin so a stolen SA token cannot be replayed against any other
 *  JWT-validating service in the cluster. The caller (workload) mounts
 *  its projected token with `audience: <this>`. */
const DEFAULT_FEDERATION_AUDIENCE = "https://auth.romaine.life";

/** Stable telemetry reason strings for the Prometheus federation
 *  counter and the JSON response body. Keep the closed set in sync
 *  with src/metrics.ts. */
export type FederationFailureReason =
  | "denied_token"
  | "denied_allowlist"
  | "denied_audience_missing"
  | "denied_audience_not_allowed"
  | "denied_ttl"
  | "error_jwt_mint"
  | "error_internal";

export class FederationExchangeError extends Error {
  constructor(
    message: string,
    public readonly status: 400 | 401 | 403 | 500,
    public readonly reason: FederationFailureReason,
  ) {
    super(message);
    this.name = "FederationExchangeError";
  }
}

export interface FederationExchangeRequest {
  /** Raw SA token from the Authorization header (sans "Bearer "). */
  saToken: string;
  /** Caller-requested audience claim for the minted JWT. Verbatim — no
   *  normalization. Must match an entry in the allowlist. */
  audience: string;
  /** Optional caller-requested TTL in seconds. Bounded by
   *  FEDERATION_MAX_TTL_SECONDS; defaults to
   *  FEDERATION_DEFAULT_TTL_SECONDS. */
  ttlSeconds?: number;
}

export interface FederationExchangeResult {
  token: string;
  /** Seconds-since-epoch when the JWT expires. Mirrors the JWT `exp`
   *  claim; surfaced so the caller can schedule a refresh without
   *  re-decoding the token. */
  expiresAt: number;
  /** The `sub` claim that was stamped — surfaced for caller-side
   *  logging / metrics so a trace line carries the same identifier
   *  the external IdP will see. */
  subject: string;
  /** Echo of the audience that was minted; matches the request body
   *  on success. */
  audience: string;
}

let cachedSaAllowlist: Set<string> | null = null;
let cachedAudienceAllowlist: string[] | null = null;

function getSaAllowlist(): Set<string> {
  if (cachedSaAllowlist) return cachedSaAllowlist;
  cachedSaAllowlist = parseAllowlist(process.env.K8S_FEDERATION_SA_ALLOWLIST ?? "");
  return cachedSaAllowlist;
}

function getAudienceAllowlist(): string[] {
  if (cachedAudienceAllowlist) return cachedAudienceAllowlist;
  cachedAudienceAllowlist = parseAudienceAllowlist(
    process.env.FEDERATION_AUDIENCE_ALLOWLIST ?? "",
  );
  return cachedAudienceAllowlist;
}

function getAudience(): string {
  return (process.env.K8S_FEDERATION_AUDIENCE ?? DEFAULT_FEDERATION_AUDIENCE).trim();
}

/** Test-only: clear cached env-derived state so a test can reset. */
export function _resetFederationExchangeCache(): void {
  cachedSaAllowlist = null;
  cachedAudienceAllowlist = null;
}

/** Exchange a verified k8s SA JWT for an external-audience federation
 *  JWT. Throws `FederationExchangeError` on any failure; the route
 *  handler maps the error to its declared status + reason. */
export async function exchangeFederationToken(
  request: FederationExchangeRequest,
): Promise<FederationExchangeResult> {
  // 0. Caller-supplied input gate. Runs BEFORE SA verify so a missing
  //    audience surfaces as a 400 rather than a 500 from the cluster
  //    OIDC verifier. The (namespace, serviceAccount) allowlist gate
  //    still runs only AFTER successful SA verify — we never reveal
  //    whether a specific subject is allowlisted to an unauthenticated
  //    caller.
  const preProblem = validateFederationRequest({
    audience: request.audience ?? "",
    ttlSeconds: request.ttlSeconds,
    audienceAllowlist: getAudienceAllowlist(),
  });
  if (preProblem && preProblem.reason === "denied_audience_missing") {
    throw new FederationExchangeError(preProblem.message, preProblem.status, preProblem.reason);
  }
  const audience = (request.audience ?? "").trim();

  // 1. Verify the inbound SA JWT against the cluster OIDC issuer and
  //    the (namespace, serviceAccount) allowlist. This is the same
  //    verifier the admin and service-exchange paths use; only the
  //    pinned audience and allowlist differ.
  let verified;
  try {
    verified = await verifyK8sSAToken(request.saToken, {
      audience: getAudience(),
      allowlist: getSaAllowlist(),
    });
  } catch (e) {
    const msg = (e as Error).message;
    if (msg.includes("not in allowlist")) {
      throw new FederationExchangeError(msg, 403, "denied_allowlist");
    }
    throw new FederationExchangeError(msg, 401, "denied_token");
  }

  // 2. Re-run the input gate for the remaining checks (audience
  //    allowlist + TTL bounds). These are post-SA-verify so a
  //    rejection is fine to surface: the caller is authenticated.
  if (preProblem) {
    throw new FederationExchangeError(preProblem.message, preProblem.status, preProblem.reason);
  }

  const subject = federationSubject(verified.namespace, verified.serviceAccount);

  let signed;
  try {
    signed = await mintFederationJwt({
      subject,
      audience,
      ttlSeconds: request.ttlSeconds ?? FEDERATION_DEFAULT_TTL_SECONDS,
    });
  } catch (e) {
    throw new FederationExchangeError(
      `mintFederationJwt failed: ${(e as Error).message}`,
      500,
      "error_jwt_mint",
    );
  }

  return {
    token: signed.token,
    expiresAt: signed.exp,
    subject,
    audience,
  };
}
