// k8s ServiceAccount token authentication for the /api/admin/origins
// surface. SA tokens are RS256 JWTs signed by the cluster's OIDC issuer —
// the same issuer that powers Azure workload identity federation for AKS.
// We validate inbound JWTs locally against the issuer's JWKS via jose,
// then gate on (namespace, serviceAccount) against an env allowlist.
//
// AuthN target: glimmung's reconciler. Glimmung's deployment mounts a
// projected SA token with `audience: https://auth.romaine.life` so that a
// stolen token cannot be replayed against other JWT-validating services.
//
// See nelsong6/glimmung#142 for the cross-repo architecture.

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

let jwksGetter: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksInitError: Error | null = null;
let jwksInitPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;

/**
 * Resolve the cluster's JWKS URL via OIDC discovery, then return a jose
 * remote JWKS getter that caches keys with its own internal TTL. Cached for
 * the lifetime of the process — the issuer doesn't change without a cluster
 * recreate (which is a full auth.romaine.life rollout anyway).
 */
async function getJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
  if (jwksGetter) return jwksGetter;
  if (jwksInitError) throw jwksInitError;
  if (jwksInitPromise) return jwksInitPromise;
  jwksInitPromise = (async () => {
    const issuer = (process.env.K8S_OIDC_ISSUER ?? "").trim();
    if (!issuer) {
      throw new Error("K8S_OIDC_ISSUER is not configured");
    }
    const discoUrl = issuer.replace(/\/$/, "") + "/.well-known/openid-configuration";
    const res = await fetch(discoUrl);
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: ${discoUrl} → HTTP ${res.status}`);
    }
    const doc = (await res.json()) as { jwks_uri?: string };
    if (!doc.jwks_uri) {
      throw new Error(`OIDC discovery doc missing jwks_uri: ${discoUrl}`);
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

export interface VerifiedK8sSA {
  namespace: string;
  serviceAccount: string;
}

interface K8sServiceAccountClaims extends JWTPayload {
  "kubernetes.io"?: {
    namespace?: string;
    serviceaccount?: { name?: string; uid?: string };
    pod?: { name?: string; uid?: string };
  };
}

/**
 * Verify a k8s ServiceAccount JWT. Throws on any failure (bad signature,
 * wrong issuer/audience, expired, missing claims, subject not allowlisted).
 * The caller should map throws to 401.
 *
 * The audience check uses `K8S_ADMIN_AUDIENCE` (default
 * `https://auth.romaine.life`). Glimmung's projected token mount MUST set
 * this audience explicitly; the default cluster audience is intentionally
 * not accepted, so a generic SA token cannot be replayed here.
 */
export async function verifyK8sSAToken(token: string): Promise<VerifiedK8sSA> {
  const issuer = (process.env.K8S_OIDC_ISSUER ?? "").trim();
  const expectedAudience = (
    process.env.K8S_ADMIN_AUDIENCE ?? "https://auth.romaine.life"
  ).trim();
  const allowlist = parseAllowlist(process.env.K8S_ADMIN_SA_ALLOWLIST ?? "");
  if (allowlist.size === 0) {
    throw new Error("K8S_ADMIN_SA_ALLOWLIST is empty; no callers are authorized");
  }

  const jwks = await getJwks();
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: expectedAudience,
  });
  const claims = payload as K8sServiceAccountClaims;
  const namespace = claims["kubernetes.io"]?.namespace?.trim();
  const serviceAccount = claims["kubernetes.io"]?.serviceaccount?.name?.trim();
  if (!namespace || !serviceAccount) {
    throw new Error("token missing kubernetes.io namespace/serviceaccount claims");
  }
  const key = `${namespace}/${serviceAccount}`;
  if (!allowlist.has(key)) {
    throw new Error(`subject not in allowlist: ${key}`);
  }
  return { namespace, serviceAccount };
}

/** Parse a comma-separated `ns/sa` allowlist. Trims entries; drops blanks
 *  and entries missing the `/` separator. Deduplicates. */
export function parseAllowlist(raw: string): Set<string> {
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && s.includes("/")),
  );
}

/** Test-only: clear the cached JWKS getter so a test can re-run init. */
export function _resetK8sAuthCache(): void {
  jwksGetter = null;
  jwksInitError = null;
  jwksInitPromise = null;
}
