// Pure helpers for the external-audience JWT federation exchange.
//
// "Federation" here means workload-identity federation in the
// RFC 7523 sense (JWT bearer / "client_assertion") — a third-party
// service (today: Tailscale) registers auth.romaine.life as a trusted
// OIDC issuer, and a romaine.life workload proves its identity to that
// third party by presenting a JWT minted here. The third party fetches
// `https://auth.romaine.life/.well-known/openid-configuration` to find
// our JWKS and verifies the signature against the same key /api/auth/jwks
// already publishes for first-party consumers.
//
// The shape is intentionally NOT the auth.romaine.life-consumer JWT
// shape: there is no `role`, no `email`, no `actor_email`, no `apps`.
// Federation tokens speak to an external verifier whose claim
// expectations come from the third party (Tailscale wants `iss`, `sub`,
// `aud`, `iat`, `exp` — pure OIDC vocabulary). Pretending to be the
// platform-internal JWT shape would mislead downstream auth.romaine.life
// consumers if such a token leaked into one of their request paths.
//
// See the route handler at /api/auth/exchange/federation in
// src/server.ts and the orchestration in src/federation-exchange.ts.

/** Maximum allowed TTL for a federation token. 15 minutes mirrors the
 *  service-token TTL in src/mint-jwt-helpers.ts — these tokens are
 *  exchanged immediately by the consumer (e.g., Tailscale's
 *  /oauth/token endpoint) for a much shorter-lived access token, so
 *  long TTLs add risk without adding ergonomic value. */
export const FEDERATION_MAX_TTL_SECONDS = 15 * 60;

/** Default TTL: 5 minutes. The consumer redeems the JWT within seconds
 *  of receiving it under normal use; 5 minutes covers clock skew and
 *  retry windows without overshooting. */
export const FEDERATION_DEFAULT_TTL_SECONDS = 5 * 60;

/** Parse the `FEDERATION_AUDIENCE_ALLOWLIST` env var.
 *
 *  Pattern grammar: comma-separated entries; trailing `*` means
 *  "match any suffix from this point" (substring match against the
 *  prefix), anything else is literal exact match. The pattern is
 *  matched against the full requested audience string verbatim — no
 *  URL parsing, no normalization — because the consumer
 *  (e.g. Tailscale) treats the audience as an opaque identifier and
 *  we should not silently normalize a `/` away.
 *
 *  Examples:
 *    "api.tailscale.com/*"      matches "api.tailscale.com/T6vF..."
 *    "api.tailscale.com/T6vF*"  matches the specific tailnet prefix
 *    "https://example.com"      matches that exact literal
 *
 *  Multiple `*` are intentionally rejected: every concrete audience
 *  pattern we expect to write is "fixed prefix + opaque tailnet/tenant
 *  id," and a multi-star pattern is almost always a typo. */
export function parseAudienceAllowlist(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Test a single audience against a parsed allowlist. Returns `true`
 *  iff at least one pattern matches. An empty allowlist refuses
 *  everything — fail-closed for misconfigured deploys. */
export function audienceAllowed(audience: string, allowlist: string[]): boolean {
  if (typeof audience !== "string" || audience.length === 0) return false;
  for (const pattern of allowlist) {
    if (matchAudiencePattern(pattern, audience)) return true;
  }
  return false;
}

/** Single-pattern matcher. Exposed for testing the pattern grammar
 *  directly. See `parseAudienceAllowlist` for the grammar. */
export function matchAudiencePattern(pattern: string, value: string): boolean {
  const stars = (pattern.match(/\*/g) ?? []).length;
  if (stars === 0) return pattern === value;
  if (stars > 1) return false;
  if (!pattern.endsWith("*")) return false;
  const prefix = pattern.slice(0, -1);
  return value.startsWith(prefix);
}

/** Validate the caller-supplied portion of a federation request before
 *  spending the SA-verify roundtrip. Returns `null` if the request
 *  is well-formed; otherwise returns a `{ status, reason, message }`
 *  triple in the shape of FederationExchangeError without depending
 *  on the orchestrator module — keeps this file dependency-free.
 *
 *  Audience gate ordering note: this runs BEFORE SA verify so an
 *  unauthenticated caller hitting the endpoint with a missing body
 *  gets a 400 (their fault — bad request) rather than a 5xx (our
 *  fault — server misconfig). The (namespace, serviceAccount)
 *  allowlist gate still runs after SA verify; we never reveal
 *  whether a specific subject is allowlisted to an unauthenticated
 *  caller. */
export interface FederationRequestProblem {
  status: 400;
  reason: "denied_audience_missing" | "denied_audience_not_allowed" | "denied_ttl";
  message: string;
}

export function validateFederationRequest(input: {
  audience: string;
  ttlSeconds?: number;
  audienceAllowlist: string[];
}): FederationRequestProblem | null {
  const audience = (input.audience ?? "").trim();
  if (audience.length === 0) {
    return {
      status: 400,
      reason: "denied_audience_missing",
      message: "audience is required",
    };
  }
  if (!audienceAllowed(audience, input.audienceAllowlist)) {
    return {
      status: 400,
      reason: "denied_audience_not_allowed",
      message: `audience ${JSON.stringify(audience)} is not in FEDERATION_AUDIENCE_ALLOWLIST`,
    };
  }
  if (input.ttlSeconds !== undefined) {
    if (!Number.isFinite(input.ttlSeconds) || input.ttlSeconds <= 0) {
      return {
        status: 400,
        reason: "denied_ttl",
        message: `ttl_seconds must be a positive number, got ${input.ttlSeconds}`,
      };
    }
    if (input.ttlSeconds > FEDERATION_MAX_TTL_SECONDS) {
      return {
        status: 400,
        reason: "denied_ttl",
        message: `ttl_seconds exceeds FEDERATION_MAX_TTL_SECONDS (${FEDERATION_MAX_TTL_SECONDS})`,
      };
    }
  }
  return null;
}

/** Derive a stable `sub` claim from a verified k8s SA identity.
 *
 *  Format: `k8s:<namespace>/<serviceAccount>`. Stable across pod
 *  restarts (the pod uid is intentionally excluded — Tailscale binds
 *  trust to a `sub` pattern, and embedding the pod uid would change
 *  the sub on every restart and break the binding). The namespace +
 *  SA pair is what's already gated by the allowlist, so the resulting
 *  `sub` is exactly as scoped as the inbound credential.
 *
 *  Traceability comes from `iat`/`exp` in the JWT plus the
 *  Prometheus counter in src/metrics.ts; per-pod uniqueness in the
 *  sub itself is not required for the external IdP path. */
export function federationSubject(namespace: string, serviceAccount: string): string {
  const ns = namespace.trim();
  const sa = serviceAccount.trim();
  if (!ns) throw new Error("federationSubject: namespace is empty");
  if (!sa) throw new Error("federationSubject: serviceAccount is empty");
  return `k8s:${ns}/${sa}`;
}
