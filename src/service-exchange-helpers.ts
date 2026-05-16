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
  | "error_jwt_mint" // upsert succeeded but signJWT threw
  | "error_internal"; // anything else (DB unreachable, etc.)

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

/** Decode the `exp` claim from a compact JWS. The body is the second
 *  segment, base64url-encoded JSON. Throws on a malformed JWT or a
 *  non-numeric `exp` — defensive against signer bugs that would
 *  otherwise hand a caller a token they couldn't schedule a refresh
 *  for. */
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
