// Pure helpers used by the service-exchange orchestrator. Split out so
// they can be unit-tested without importing the DB client or Better
// Auth (both of which require runtime env at module init).

/** Telemetry-grade reason for an exchange failure. Stable string set —
 *  if you add a value here, also extend the counter labels documented
 *  in nelsong6/tank-operator#486 Stage 5 observability. */
export type ExchangeFailureReason =
  | "denied_token" // signature, issuer, audience, expiry, or claim shape
  | "denied_allowlist" // (ns, sa) not in K8S_SERVICE_SA_ALLOWLIST
  | "denied_unbound_pod" // SA token has no kubernetes.io.pod ref
  | "denied_unknown_namespace" // namespace not mapped to a consumer
  | "denied_annotation_missing" // pod missing owner-email or session-id
  | "denied_pod_lookup_failed" // pod-GET failed (404, 403, transport)
  | "denied_actor_override_not_allowed" // requested actor_email but consumer is not elevated
  | "denied_actor_email_invalid" // supplied actor_email failed format validation
  | "error_jwt_mint" // upsert succeeded but signJWT threw
  | "error_internal"; // anything else (DB unreachable, etc.)

/** Permissive email-shape validator for the on-behalf-of actor override.
 *  Mirrors what auth.romaine.life accepts from upstream IdPs: any
 *  non-empty `local@domain` with at least one `.` in the domain. Reject
 *  obvious garbage at the route boundary so the JWT can't carry
 *  malformed values that downstream consumers (mcp-github, the
 *  orchestrator's own `/api/internal/github/installation`) will then
 *  have to handle. Not a full RFC 5322 check — the IdP doesn't do that
 *  either, and the privilege gate (caller must be an `allowActorOverride`
 *  consumer) is the actual security boundary. */
const ACTOR_EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function isPlausibleActorEmail(value: string): boolean {
  return ACTOR_EMAIL_PATTERN.test(value.trim());
}

export class ExchangeError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly reason: ExchangeFailureReason,
  ) {
    super(message);
    this.name = "ExchangeError";
  }
}

/** Build the Better Auth user id for a service principal. `svc:` prefix
 *  structurally distinguishes service users from human users in any
 *  DB-side query, audit log, or admin console; the colon-separated
 *  shape mirrors the JWT `sub` semantics commonly used by cloud IAMs
 *  (e.g., "spiffe://..."). Deterministic per (consumer, sessionId) so
 *  the upsert is idempotent across pod restarts. */
export function serviceUserId(consumer: string, sessionId: string): string {
  return `svc:${consumer}:${sessionId}`;
}

// `extractExpClaim` used to live here. It was a runtime workaround for
// the era when mint sites called Better Auth's `signJWT` directly and
// needed to re-decode the JWT to learn its `exp`. With every mint now
// routed through `mintAuthJwt` (src/mint-jwt.ts) — which stamps and
// returns `iat`/`exp` on the result — there is no caller left. Deleted
// rather than kept as a "just in case" helper, per
// docs/migration-policy.md (no runtime reads whose purpose is to keep
// old behavior working).
