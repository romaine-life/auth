// Single mint site for all auth.romaine.life-signed JWTs.
//
// This is the ONLY place in src/ that calls Better Auth's `signJWT`.
// The CI guard at scripts/check-signjwt-callsites.mjs enforces that;
// callers that need a token import `mintAuthJwt` or `mintFederationJwt`
// instead. Concentrating both shapes here means a single audit point
// covers every key the JWT plugin (and JWKS endpoint) publishes.
//
// Two shapes live here:
//
//  - `mintAuthJwt`: the platform-internal JWT. iss/aud are derived from
//    baseURL by Better Auth's signJWT defaults. Consumers are
//    auth.romaine.life-side verifiers (homepage, glimmung, mcp-github,
//    tank-operator) that pin REQUIRED_CLAIMS including `role`. See
//    src/mint-jwt-helpers.ts for the payload contract.
//
//  - `mintFederationJwt`: an external-audience JWT for RFC 7523
//    JWT-bearer / "client_assertion" flows where a third-party IdP
//    (today: Tailscale's "Trust credentials" OIDC type) treats
//    auth.romaine.life as a trusted issuer and our JWKS as the trust
//    root. iss stays `https://auth.romaine.life` (matches the discovery
//    doc the consumer fetches) but aud is the third party's identifier
//    and there is no `role` / `email` / `actor_email` / `apps` — those
//    are platform-internal claims with no meaning to Tailscale.
//
// Better Auth's `signJWT` honors a payload-supplied `aud` and `iss`
// (verified empirically against node_modules/better-auth/dist/plugins/
// jwt/sign.mjs at v1.6: `aud: payload.aud ?? defaultAud`). That is
// load-bearing for `mintFederationJwt`; if a future Better Auth
// version starts overwriting aud from baseURL we have to switch to
// signing with jose directly against the JWKS table.

import { auth } from "./auth.js";
import {
  assertBuilderClaimsPresent,
  buildAuthJwtPayload,
  type AuthJwtInput,
} from "./mint-jwt-helpers.js";
import {
  FEDERATION_DEFAULT_TTL_SECONDS,
  FEDERATION_MAX_TTL_SECONDS,
} from "./federation-helpers.js";

export interface MintResult {
  token: string;
  iat: number;
  exp: number;
}

export async function mintAuthJwt(input: AuthJwtInput): Promise<MintResult> {
  const payload = buildAuthJwtPayload(input);
  assertBuilderClaimsPresent(payload);
  // eslint-disable-next-line no-restricted-syntax -- This is one of the
  // two sanctioned signJWT call sites; scripts/check-signjwt-callsites.mjs
  // enforces that all signJWT usage lives in this file.
  const signed = await auth.api.signJWT({ body: { payload } });
  return { token: signed.token, iat: payload.iat, exp: payload.exp };
}

/** Inputs to a federation-JWT mint. `audience` is verbatim — the route
 *  handler validates it against the allowlist before calling.
 *
 *  `subject` is the caller-derived `sub`; for the k8s SA → federation
 *  path it's `federationSubject(namespace, sa)` (see
 *  src/federation-helpers.ts).
 *
 *  `ttlSeconds` defaults to FEDERATION_DEFAULT_TTL_SECONDS; bounded by
 *  FEDERATION_MAX_TTL_SECONDS so a misconfigured caller can't mint a
 *  long-lived external-audience credential. */
export interface FederationJwtInput {
  subject: string;
  audience: string;
  ttlSeconds?: number;
}

export async function mintFederationJwt(input: FederationJwtInput): Promise<MintResult> {
  if (typeof input.subject !== "string" || input.subject.length === 0) {
    throw new Error("mintFederationJwt: subject is required");
  }
  if (typeof input.audience !== "string" || input.audience.length === 0) {
    throw new Error("mintFederationJwt: audience is required");
  }
  const ttl = input.ttlSeconds ?? FEDERATION_DEFAULT_TTL_SECONDS;
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new Error(`mintFederationJwt: ttlSeconds must be positive, got ${ttl}`);
  }
  if (ttl > FEDERATION_MAX_TTL_SECONDS) {
    throw new Error(
      `mintFederationJwt: ttlSeconds exceeds FEDERATION_MAX_TTL_SECONDS (${FEDERATION_MAX_TTL_SECONDS}): ${ttl}`,
    );
  }
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;
  // No `role`/`email`/`actor_email`/`apps` here — see the file header.
  // signJWT reads `iss`/`aud`/`sub`/`iat`/`exp` off the payload object
  // and sets them on the JWT via jose's SignJWT builder; everything
  // else on the payload is included verbatim. Keeping the payload
  // minimal is the contract with the external consumer.
  const payload = {
    iss: "https://auth.romaine.life",
    aud: input.audience,
    sub: input.subject,
    iat,
    exp,
  };
  // eslint-disable-next-line no-restricted-syntax -- This is one of the
  // two sanctioned signJWT call sites; scripts/check-signjwt-callsites.mjs
  // enforces that all signJWT usage lives in this file.
  const signed = await auth.api.signJWT({ body: { payload } });
  return { token: signed.token, iat, exp };
}

