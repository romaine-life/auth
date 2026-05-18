// Synthetic email construction and reserved-domain guard for service
// principals.
//
// Service principals (k8s pods that authenticate via SA token exchange) are
// stored as Better Auth users like any other principal — Better Auth's
// schema requires a non-null, unique email per user. We give them an email
// under a DNS subdomain we control but never serve MX on, so the
// synthetic-ness is structural: no human Microsoft / Google account can ever
// be issued under these names.
//
// Per-consumer subdomain convention: each in-cluster service that mints
// service principals on its behalf gets its own subdomain
// (`service.<consumer>.romaine.life`). Scales when new consumers arrive
// (glimmung, ambience, etc.) and makes the issuing consumer obvious from
// the email alone.
//
// Pattern is borrowed from GitLab service accounts
// (service_account_<hash>@noreply.gitlab.example.com) and GitHub App bots
// (<id>+<name>[bot]@users.noreply.github.com).
//
// See nelsong6/tank-operator#486.

/**
 * The set of DNS subdomains reserved for synthetic service-principal emails.
 * Anything under one of these is _by construction_ a service principal, not
 * a human user. The Better Auth `databaseHooks.user.create.before` hook
 * (in src/auth.ts) refuses to create a user whose email matches one of
 * these from any social-OAuth provider — defense in depth against an IdP
 * spoofing a service principal.
 *
 * Add to this list when onboarding a new consumer (one entry per
 * `service.<consumer>.romaine.life`). The `service-exchange` minter is
 * still per-consumer; this list is just the cross-cutting guard.
 */
export const RESERVED_SERVICE_EMAIL_DOMAINS: readonly string[] = [
  "service.tank.romaine.life",
  "service.mcp-k8s.romaine.life",
  "service.mcp-argocd.romaine.life",
  "service.mcp-azure-personal.romaine.life",
  // Hermes (`nelsong6/hermes`) is a singleton StatefulSet — one pod
  // serves many users; no per-pod human actor. Onboarded as a
  // pod-stable consumer (same shape as the mcp-* shared servers above)
  // so the exchange skips annotation reads and uses a fixed stableId.
  // See nelsong6/tank-operator#540.
  "service.hermes.romaine.life",
];

/** Build the synthetic email for a service principal owned by `consumer`,
 *  keyed by `stableId`. The id is a stable identifier from the
 *  consumer's perspective (e.g. a tank-operator session-id) — pod restarts
 *  must NOT change it, otherwise the user table churns and audit/quota
 *  attach to the wrong row. */
export function buildServiceEmail(consumer: string, stableId: string): string {
  const c = consumer.trim();
  const s = stableId.trim();
  if (!c) throw new Error("consumer must be non-empty");
  if (!s) throw new Error("stableId must be non-empty");
  if (!/^[a-z0-9-]+$/.test(c)) {
    throw new Error(`consumer must be lowercase a-z 0-9 -: ${consumer}`);
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(s)) {
    throw new Error(`stableId must be [A-Za-z0-9_-]+: ${stableId}`);
  }
  const domain = `service.${c}.romaine.life`;
  if (!RESERVED_SERVICE_EMAIL_DOMAINS.includes(domain)) {
    // Force callers to register new consumers in RESERVED_SERVICE_EMAIL_DOMAINS
    // before minting under them. Without this, a typo in `consumer` would
    // create users under an unguarded domain — a human signing in via an
    // IdP that happened to control that domain could collide.
    throw new Error(
      `domain ${domain} is not in RESERVED_SERVICE_EMAIL_DOMAINS; ` +
        `register the new consumer before issuing service principals under it`,
    );
  }
  return `pod-${s}@${domain}`;
}

/** Build the display name for a service principal — surfaces in the auth
 *  admin console and downstream apps. Keep distinct from a human name so
 *  no UI accidentally renders it as a person. */
export function buildServiceName(consumer: string, stableId: string): string {
  return `Service: ${consumer.trim()} pod-${stableId.trim()}`;
}

/** True iff `email` is in one of the reserved synthetic-email domains.
 *  Used by the Microsoft / Google OAuth callback guard so an IdP-issued
 *  email under our reserved namespace gets refused before a row is
 *  inserted. Case-insensitive on the domain (email addresses' local-part
 *  case is preserved). */
export function isReservedServiceEmail(email: string): boolean {
  const at = email.lastIndexOf("@");
  if (at < 0) return false;
  const domain = email.slice(at + 1).toLowerCase();
  return RESERVED_SERVICE_EMAIL_DOMAINS.includes(domain);
}
