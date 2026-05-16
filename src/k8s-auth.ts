// k8s ServiceAccount token authentication. SA tokens are RS256 JWTs signed
// by the cluster's OIDC issuer — the same issuer that powers Azure workload
// identity federation for AKS. We validate inbound JWTs locally against the
// issuer's JWKS via jose, then gate on (namespace, serviceAccount) against
// a caller-supplied allowlist.
//
// Two callers today:
//   1. /api/admin/origins/* — glimmung's reconciler writes here. SA tokens
//      come from glimmung's projected token mount. See nelsong6/glimmung#142.
//   2. /api/auth/exchange/k8s — tank-operator session pods exchange their
//      projected SA token here for an auth.romaine.life service-principal
//      JWT. See nelsong6/tank-operator#486.
//
// Both callers use the same RS256+JWKS+allowlist verification path; what
// differs is the audience pin and the allowlist contents. `verifyK8sSAToken`
// is the shared verifier and accepts both as options.

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
  /** Bound pod metadata when the SA token was minted with bound objects.
   *  Standard projected SA tokens in k8s include this. Absent for legacy
   *  long-lived SA tokens — the service-exchange caller requires it and
   *  rejects when missing. */
  pod?: { name: string; uid: string };
}

interface K8sServiceAccountClaims extends JWTPayload {
  "kubernetes.io"?: {
    namespace?: string;
    serviceaccount?: { name?: string; uid?: string };
    pod?: { name?: string; uid?: string };
  };
}

export interface VerifyK8sSATokenOptions {
  /** The audience claim the inbound token must carry. SA tokens are minted
   *  per consumer (`audience: <this>`) so a stolen token cannot be replayed
   *  against any other JWT-validating service in the cluster. No default —
   *  callers must pin one. */
  audience: string;
  /** Allowlist of `${namespace}/${serviceAccount}` strings. Empty allowlist
   *  rejects everything (intentional — a misconfigured env should fail
   *  closed). Pre-parsed by the caller via `parseAllowlist`. */
  allowlist: Set<string>;
}

/**
 * Verify a k8s ServiceAccount JWT against the configured OIDC issuer and
 * the caller-supplied (audience, allowlist) pair. Throws on any failure
 * (bad signature, wrong issuer/audience, expired, missing claims, subject
 * not allowlisted). The HTTP caller should map throws to 401.
 */
export async function verifyK8sSAToken(
  token: string,
  options: VerifyK8sSATokenOptions,
): Promise<VerifiedK8sSA> {
  const issuer = (process.env.K8S_OIDC_ISSUER ?? "").trim();
  if (!issuer) {
    throw new Error("K8S_OIDC_ISSUER is not configured");
  }
  if (options.allowlist.size === 0) {
    throw new Error("allowlist is empty; no callers are authorized");
  }

  const jwks = await getJwks();
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: options.audience,
  });
  const claims = payload as K8sServiceAccountClaims;
  const namespace = claims["kubernetes.io"]?.namespace?.trim();
  const serviceAccount = claims["kubernetes.io"]?.serviceaccount?.name?.trim();
  if (!namespace || !serviceAccount) {
    throw new Error("token missing kubernetes.io namespace/serviceaccount claims");
  }
  const key = `${namespace}/${serviceAccount}`;
  if (!options.allowlist.has(key)) {
    throw new Error(`subject not in allowlist: ${key}`);
  }
  const podName = claims["kubernetes.io"]?.pod?.name?.trim();
  const podUid = claims["kubernetes.io"]?.pod?.uid?.trim();
  return {
    namespace,
    serviceAccount,
    pod: podName && podUid ? { name: podName, uid: podUid } : undefined,
  };
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
