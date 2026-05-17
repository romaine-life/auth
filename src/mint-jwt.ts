// Single mint site for auth.romaine.life JWTs.
//
// This is the ONLY place in src/ that calls Better Auth's `signJWT`.
// The CI guard at scripts/check-signjwt-callsites.mjs enforces that;
// callers that need a token import `mintAuthJwt` instead.
//
// The split between mint-jwt-helpers.ts (pure payload construction)
// and this file (signJWT call) keeps the contract logic unit-testable
// without a live Better Auth instance.
//
// Behaviour:
//   - Stamps `iat` (now) and `exp` (now + ttl). Caller-supplied TTL
//     defaults to TTL_SECONDS[purpose] from the helpers module; the
//     helpers refuse a TTL outside (0, MAX_TTL_SECONDS].
//   - Delegates `iss` and `aud` to Better Auth's signJWT — it derives
//     them from `baseURL`, so a config rename can't desync them.
//   - Returns the compact JWT plus the stamped iat/exp so callers can
//     log them without re-decoding the token.

import { auth } from "./auth.js";
import {
  type AuthJwtInput,
  assertBuilderClaimsPresent,
  buildAuthJwtPayload,
} from "./mint-jwt-helpers.js";

export interface MintResult {
  token: string;
  iat: number;
  exp: number;
}

export async function mintAuthJwt(input: AuthJwtInput): Promise<MintResult> {
  const payload = buildAuthJwtPayload(input);
  assertBuilderClaimsPresent(payload);
  // eslint-disable-next-line no-restricted-syntax -- This is the single
  // sanctioned signJWT call site; every other call is rejected by
  // scripts/check-signjwt-callsites.mjs.
  const signed = await auth.api.signJWT({ body: { payload } });
  return { token: signed.token, iat: payload.iat, exp: payload.exp };
}
