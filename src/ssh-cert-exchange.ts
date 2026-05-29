// k8s SA-token → OpenSSH user-certificate exchange.
//
// Inbound: a workload (today: glimmung's native-runner callback, acting
// as a per-run issuance gateway) presents its projected k8s
// ServiceAccount token and a freshly-minted ed25519 public key, asking
// auth to sign a short-lived OpenSSH *user certificate* over it.
// Outbound: a marshaled cert (principal `<project>-agent`, permit-pty
// only, ≤10 min) that a remote host trusts because its
// TrustedUserCAKeys names auth.romaine.life's SSH CA public key.
//
// Why this is structurally separate from src/federation-exchange.ts and
// src/service-exchange.ts:
//   - Different signing KEY CLASS. Federation/service mint JWTs with the
//     JWKS key (src/mint-jwt.ts → Better Auth signJWT). This mints an
//     OpenSSH certificate with a separate ed25519 SSH CA key
//     (SSH_CA_PRIVATE_KEY). A JWT verifier must never see this key and an
//     sshd must never see the JWKS key.
//   - Different inbound allowlist (K8S_SSH_CERT_SA_ALLOWLIST). Trust to
//     mint a Tailscale-audience JWT is NOT trust to mint a host login
//     credential; conflating the allowlists would hand every existing
//     federation caller SSH-cert minting power the day this lands.
//   - Different output: an SSH cert is a host login credential, not a
//     bearer token for a romaine.life verifier.
//
// This endpoint is the auth side of the migration that retires
// glimmung's local SSH CA (glimmung/internal/server/ssh_ca.go +
// GLIMMUNG_SSH_CA_PRIVATE_KEY). The CA key and the signing operation move
// here; glimmung keeps only the per-run gateway that derives the
// run-scoped key_id/principal and calls this endpoint.

import { parseAllowlist, verifyK8sSAToken } from "./k8s-auth.js";
import {
  compilePrincipalPattern,
  validateSshCertRequest,
  type SshCertRequestProblem,
  type ValidatedSshCertRequest,
} from "./ssh-cert-helpers.js";
import {
  SshCaUnconfiguredError,
  SshCertSigner,
  SSH_CERT_SKEW_SECONDS,
  parseUserEd25519PublicKey,
} from "./ssh-cert.js";

/** Audience pinned on inbound SA tokens. Mirrors the federation/service
 *  pins so a stolen SA token minted for a different audience cannot be
 *  replayed here. The caller mounts its projected token with
 *  `audience: https://auth.romaine.life`. */
const DEFAULT_SSH_CERT_AUDIENCE = "https://auth.romaine.life";

export type SshCertExchangeReason =
  | "denied_token"
  | "denied_allowlist"
  | "denied_public_key"
  | "denied_key_id"
  | "denied_principal"
  | "denied_extension"
  | "denied_ttl"
  | "error_ca_unconfigured"
  | "error_sign"
  | "error_internal";

export class SshCertExchangeError extends Error {
  constructor(
    message: string,
    public readonly status: 400 | 401 | 403 | 500 | 503,
    public readonly reason: SshCertExchangeReason,
  ) {
    super(message);
    this.name = "SshCertExchangeError";
  }
}

export interface SshCertExchangeRequest {
  saToken: string;
  publicKey: unknown;
  keyId: unknown;
  principals: unknown;
  extensions?: unknown;
  ttlSeconds?: unknown;
}

export interface SshCertExchangeResult {
  /** `ssh-ed25519-cert-v01@openssh.com <base64>` — write to a
   *  `-cert.pub` file and pass to `ssh -i key -o CertificateFile=…`. */
  certificate: string;
  /** Seconds-since-epoch the cert expires (mirrors ValidBefore). */
  validBefore: number;
  /** The `k8s:<ns>/<sa>` subject that requested issuance — surfaced for
   *  the caller's trace line; matches the audit log on the auth side. */
  subject: string;
  /** Echo of the validated key_id stamped onto the cert. */
  keyId: string;
  /** Echo of the validated principals stamped onto the cert. */
  principals: string[];
}

let cachedSaAllowlist: Set<string> | null = null;
let cachedSigner: SshCertSigner | null = null;
let cachedSignerError: Error | null = null;
let cachedPrincipalPattern: RegExp | null = null;

function getSaAllowlist(): Set<string> {
  if (cachedSaAllowlist) return cachedSaAllowlist;
  cachedSaAllowlist = parseAllowlist(process.env.K8S_SSH_CERT_SA_ALLOWLIST ?? "");
  return cachedSaAllowlist;
}

function getAudience(): string {
  return (process.env.K8S_SSH_CERT_AUDIENCE ?? DEFAULT_SSH_CERT_AUDIENCE).trim();
}

function getPrincipalPattern(): RegExp {
  if (cachedPrincipalPattern) return cachedPrincipalPattern;
  cachedPrincipalPattern = compilePrincipalPattern(process.env.SSH_CERT_PRINCIPAL_PATTERN);
  return cachedPrincipalPattern;
}

/** Lazily load + cache the CA signer. A missing/invalid key is cached as
 *  an error and surfaced as 503 so the endpoint fails closed: a missing
 *  CA must never silently bypass cert issuance, and it must never crash
 *  the rest of the auth service either (federation, sign-in, etc. stay
 *  up). */
function getSigner(): SshCertSigner {
  if (cachedSigner) return cachedSigner;
  if (cachedSignerError) throw cachedSignerError;
  try {
    cachedSigner = SshCertSigner.fromPkcs8Pem(process.env.SSH_CA_PRIVATE_KEY ?? "");
    return cachedSigner;
  } catch (e) {
    cachedSignerError = e instanceof Error ? e : new Error(String(e));
    throw cachedSignerError;
  }
}

/** Whether the CA key is configured. Drives the public-key endpoint's
 *  404 and lets a readiness check assert issuance is wired. */
export function isSshCaConfigured(): boolean {
  try {
    getSigner();
    return true;
  } catch {
    return false;
  }
}

/** The CA public key as a TrustedUserCAKeys line, or null when the CA is
 *  unconfigured. Served unauthenticated at GET /api/ssh/ca — a CA public
 *  key is published-by-design (hosts fetch it to populate
 *  TrustedUserCAKeys). */
export function sshCaPublicKey(): string | null {
  try {
    return getSigner().publicKeyAuthorizedKey();
  } catch {
    return null;
  }
}

/** Test-only: clear cached env/key-derived state. */
export function _resetSshCertExchangeCache(): void {
  cachedSaAllowlist = null;
  cachedSigner = null;
  cachedSignerError = null;
  cachedPrincipalPattern = null;
}

export async function exchangeSshCert(
  request: SshCertExchangeRequest,
): Promise<SshCertExchangeResult> {
  // 0. Validate caller-supplied body BEFORE the SA-verify roundtrip so a
  //    malformed request is the caller's 400, not a wasted verify. The
  //    (namespace, serviceAccount) allowlist gate still runs only AFTER
  //    SA verify — we never reveal whether a subject is allowlisted to an
  //    unauthenticated caller.
  const validated = validateSshCertRequest({
    publicKey: request.publicKey,
    keyId: request.keyId,
    principals: request.principals,
    extensions: request.extensions,
    ttlSeconds: request.ttlSeconds,
    principalPattern: getPrincipalPattern(),
  });
  if (isProblem(validated)) {
    throw new SshCertExchangeError(validated.message, validated.status, validated.reason);
  }

  // 1. Verify the inbound SA JWT against the cluster OIDC issuer + the
  //    SSH-cert allowlist. Same verifier as admin/service/federation;
  //    only the pinned audience + allowlist differ.
  let verified;
  try {
    verified = await verifyK8sSAToken(request.saToken, {
      audience: getAudience(),
      allowlist: getSaAllowlist(),
    });
  } catch (e) {
    const msg = (e as Error).message;
    if (msg.includes("not in allowlist")) {
      throw new SshCertExchangeError(msg, 403, "denied_allowlist");
    }
    throw new SshCertExchangeError(msg, 401, "denied_token");
  }

  const subject = `k8s:${verified.namespace}/${verified.serviceAccount}`;

  // 2. Parse the user public key (ed25519 only) — its own failure class
  //    so a bad key reads as denied_public_key, not a generic sign error.
  let userPublicKey;
  try {
    userPublicKey = parseUserEd25519PublicKey(validated.publicKey);
  } catch (e) {
    throw new SshCertExchangeError((e as Error).message, 400, "denied_public_key");
  }

  // 3. Load the CA + sign. CA-unconfigured is a 503 (fail closed);
  //    anything else in the sign path is a 500.
  let signer: SshCertSigner;
  try {
    signer = getSigner();
  } catch (e) {
    if (e instanceof SshCaUnconfiguredError) {
      throw new SshCertExchangeError(e.message, 503, "error_ca_unconfigured");
    }
    throw new SshCertExchangeError(
      `SSH CA load failed: ${(e as Error).message}`,
      503,
      "error_ca_unconfigured",
    );
  }

  const now = Math.floor(Date.now() / 1000);
  let signed;
  try {
    signed = signer.signUserCert({
      userPublicKey,
      keyId: validated.keyId,
      principals: validated.principals,
      extensions: validated.extensions,
      validAfter: now - SSH_CERT_SKEW_SECONDS,
      validBefore: now + validated.ttlSeconds,
    });
  } catch (e) {
    throw new SshCertExchangeError(
      `sign SSH cert failed: ${(e as Error).message}`,
      500,
      "error_sign",
    );
  }

  return {
    certificate: signed.authorizedKeyLine,
    validBefore: signed.validBefore,
    subject,
    keyId: validated.keyId,
    principals: validated.principals,
  };
}

function isProblem(
  v: SshCertRequestProblem | ValidatedSshCertRequest,
): v is SshCertRequestProblem {
  return (v as SshCertRequestProblem).status === 400 && "reason" in v;
}
