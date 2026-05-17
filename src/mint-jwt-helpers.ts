// Pure helpers for the auth.romaine.life JWT mint contract.
//
// Every auth.romaine.life-issued JWT — whether for a human signing in,
// an admin minting a 24h CLI bot token, or a service principal exchanging
// a k8s SA token — is consumed by the same verifier contract. The shared
// verifier library at nelsong6/romaine-auth-py and the duplicated
// verifier in nelsong6/mcp-github both pin the required-claim set to:
//
//     ["exp", "iat", "iss", "role"]
//
// Plus `actor_email` for role=service tokens. Any token we mint must
// satisfy that contract; if it doesn't, every downstream MCP rejects it
// with a verbose "missing claim" error that surfaces as a 5xx in the
// session pod.
//
// Why this file exists: previously each mint site composed its own
// payload and called `auth.api.signJWT` directly. The bot-token site
// happened to stamp `iat` and `exp` explicitly; the service-exchange
// site relied on Better Auth's `signJWT` defaults, which set
// `iss`/`aud`/`exp` but NOT `iat`. The two paths drifted silently — the
// drop fell out only when mcp-github started rejecting service tokens
// with `Token is missing the "iat" claim`. The shared mint helper +
// CI guard at scripts/check-signjwt-callsites.mjs is the migration
// guard against that class of regression.
//
// Tests for the contract are co-located in mint-jwt-helpers.test.ts.

/** The required-claim set every auth.romaine.life consumer pins. Keep
 *  this list in sync with `require` in nelsong6/romaine-auth-py and
 *  the bespoke duplicate in nelsong6/mcp-github → auth_romaine.py.
 *  Adding a key here is a cross-repo contract change. */
export const REQUIRED_CLAIMS = ["exp", "iat", "iss", "role"] as const;

/** Roles that any consumer of an auth.romaine.life JWT will accept.
 *  Mirrors `ALLOWED_ROLES` in nelsong6/romaine-auth-py. `pending` is
 *  intentionally absent — pending users have authenticated but not
 *  been promoted; downstream apps refuse them. */
export const ALLOWED_ROLES = ["admin", "user", "service"] as const;
export type AllowedRole = (typeof ALLOWED_ROLES)[number];

/** Default TTLs by mint purpose. Bot tokens get 24h because they are
 *  copy-pasted into curl commands; service tokens get 15min because
 *  they are minted on every cold exchange and refreshed cheaply. */
export const TTL_SECONDS = {
  service: 15 * 60,
  bot: 24 * 60 * 60,
} as const;

/** Caller-controlled inputs to a mint. The helper composes the full
 *  payload from these; it does NOT accept raw `iat`/`exp` because the
 *  whole point is to centralize claim stamping. Pass `ttlSeconds` to
 *  override the default for the role/purpose. */
export interface AuthJwtInput {
  sub: string;
  email: string;
  name: string;
  role: AllowedRole;
  /** Free-form per-user app prefs blob. Standard for human + bot
   *  tokens; service tokens pass `{}` because per-app prefs are a
   *  human concept. */
  apps: Record<string, unknown>;
  /** Required when role=service: the human whose session this token
   *  is acting on behalf of. Verifier refuses service tokens missing
   *  it. Forbidden for non-service tokens — they don't have an actor. */
  actorEmail?: string;
  /** Optional `purpose` claim. Bot tokens carry `"bot"`; service
   *  tokens leave it unset. Surface for audit and for routing
   *  decisions in consumers (e.g., bot tokens skip refresh storms). */
  purpose?: string;
  /** TTL override in seconds. Defaults to TTL_SECONDS[bot|service]
   *  or 15min if neither matches. Bounded — refuse anything past 7d
   *  to keep blast radius of a leaked token bounded. */
  ttlSeconds?: number;
}

/** Maximum allowed TTL for any mint. 7 days mirrors the SPA-cookie
 *  TTL; nothing minted here should outlive that. */
export const MAX_TTL_SECONDS = 7 * 24 * 60 * 60;

/** Output of buildAuthJwtPayload — the literal JSON object passed to
 *  Better Auth's `signJWT`. iss/aud are intentionally absent: Better
 *  Auth's signJWT fills them from `baseURL`, and we keep that
 *  delegation so a base-URL rename doesn't desync iss with reality.
 *  Everything else on the verifier require-list is stamped here.
 *  Index signature lets us round-trip through JWTPayload (which is
 *  `Record<string, unknown>`-shaped in jose / better-auth) without an
 *  unsafe-cast escape hatch at the mint site. */
export interface AuthJwtPayload {
  sub: string;
  email: string;
  name: string;
  role: AllowedRole;
  apps: Record<string, unknown>;
  iat: number;
  exp: number;
  actor_email?: string;
  purpose?: string;
  [key: string]: unknown;
}

/** Build the payload for an auth.romaine.life JWT mint. Pure — takes a
 *  clock for testability. Throws on contract violations (bad role,
 *  service token without actor_email, TTL out of bounds). */
export function buildAuthJwtPayload(
  input: AuthJwtInput,
  now: () => number = () => Math.floor(Date.now() / 1000),
): AuthJwtPayload {
  if (!ALLOWED_ROLES.includes(input.role)) {
    throw new Error(`role not in ALLOWED_ROLES: ${JSON.stringify(input.role)}`);
  }
  if (input.role === "service") {
    if (!input.actorEmail || !input.actorEmail.trim()) {
      throw new Error("service tokens require a non-empty actorEmail");
    }
  } else if (input.actorEmail !== undefined) {
    throw new Error("non-service tokens must not carry actorEmail");
  }

  const defaultTtl =
    input.purpose === "bot"
      ? TTL_SECONDS.bot
      : input.role === "service"
        ? TTL_SECONDS.service
        : TTL_SECONDS.service;
  const ttl = input.ttlSeconds ?? defaultTtl;
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new Error(`ttlSeconds must be a positive number, got ${ttl}`);
  }
  if (ttl > MAX_TTL_SECONDS) {
    throw new Error(`ttlSeconds exceeds MAX_TTL_SECONDS (${MAX_TTL_SECONDS}): ${ttl}`);
  }

  const iat = now();
  const exp = iat + ttl;

  const payload: AuthJwtPayload = {
    sub: input.sub,
    email: input.email,
    name: input.name,
    role: input.role,
    apps: input.apps,
    iat,
    exp,
  };
  if (input.actorEmail !== undefined) {
    payload.actor_email = input.actorEmail;
  }
  if (input.purpose !== undefined) {
    payload.purpose = input.purpose;
  }
  return payload;
}

/** Assert every claim in REQUIRED_CLAIMS appears on the payload as a
 *  non-empty value. Cheap defense-in-depth — runs after build so a
 *  future contract addition (e.g., adding `nbf`) trips loudly if the
 *  builder forgets to stamp it.
 *
 *  NOTE: REQUIRED_CLAIMS lists `iss`, which the builder does NOT
 *  stamp — Better Auth's signJWT fills it from baseURL. The verifier
 *  contract test downstream of `signJWT` is the right place to assert
 *  `iss`; here we just check the claims this helper owns. */
export function assertBuilderClaimsPresent(payload: AuthJwtPayload): void {
  const builderOwned = REQUIRED_CLAIMS.filter((k) => k !== "iss");
  for (const claim of builderOwned) {
    const value = (payload as Record<string, unknown>)[claim];
    if (value === undefined || value === null || value === "") {
      throw new Error(
        `mint contract violation: payload missing required claim ${JSON.stringify(claim)}`,
      );
    }
  }
}
