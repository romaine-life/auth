// Pure, dependency-free validation for the SSH user-cert exchange.
//
// The exchange endpoint trusts the caller for NONE of the
// security-relevant cert fields: principals, extensions, and TTL are all
// validated/bounded here BEFORE the CA key signs anything. A caller that
// asks for a principal outside the allowlist pattern, an extension auth
// won't stamp, or a TTL beyond the ceiling is REJECTED — never silently
// downgraded — so a misconfigured (or compromised) caller surfaces as a
// 4xx instead of a quietly-weakened credential.
//
// See src/ssh-cert.ts for the signing primitive and
// src/ssh-cert-exchange.ts for the orchestration.

import {
  SSH_CERT_ALLOWED_EXTENSIONS,
  SSH_CERT_DEFAULT_TTL_SECONDS,
  SSH_CERT_MAX_TTL_SECONDS,
  SSH_CERT_MIN_TTL_SECONDS,
} from "./ssh-cert.js";

/** Default principal grammar: glimmung derives the principal as
 *  `<project>-agent` (e.g. `spirelens-agent`). The pattern is
 *  overridable via SSH_CERT_PRINCIPAL_PATTERN for a future consumer with
 *  a different naming scheme, but the default fails closed to the
 *  `-agent` suffix so a caller can't request `root` or an arbitrary
 *  login name. */
export const DEFAULT_PRINCIPAL_PATTERN = "^[a-z0-9][a-z0-9-]{0,62}-agent$";

/** Cap on principals per cert. A run needs exactly one; the cap stops a
 *  caller from stuffing a cert with many identities. */
export const SSH_CERT_MAX_PRINCIPALS = 4;

/** Cap on key_id length. The key_id is logged by sshd on every auth and
 *  is the host-side audit handle; bound it so it can't be abused as an
 *  unbounded log-injection vector. */
export const SSH_CERT_MAX_KEY_ID_LENGTH = 256;

export type SshCertRequestProblemReason =
  | "denied_public_key"
  | "denied_key_id"
  | "denied_principal"
  | "denied_extension"
  | "denied_ttl";

export interface SshCertRequestProblem {
  status: 400;
  reason: SshCertRequestProblemReason;
  message: string;
}

export interface ValidatedSshCertRequest {
  publicKey: string;
  keyId: string;
  principals: string[];
  extensions: string[];
  ttlSeconds: number;
}

export interface SshCertRequestInput {
  publicKey: unknown;
  keyId: unknown;
  principals: unknown;
  extensions?: unknown;
  ttlSeconds?: unknown;
  principalPattern: RegExp;
}

/** Validate and normalize the caller-supplied portion of an SSH cert
 *  request. Returns either a problem (caller's fault → 400) or the
 *  validated request. Does NOT touch the SA token or the CA key — those
 *  are the orchestrator's job. Dependency-free so it can be unit-tested
 *  without env or crypto. */
export function validateSshCertRequest(
  input: SshCertRequestInput,
): SshCertRequestProblem | ValidatedSshCertRequest {
  // public_key: presence + type only; cryptographic parse happens in the
  // signer layer (parseUserEd25519PublicKey) which owns the format rules.
  if (typeof input.publicKey !== "string" || input.publicKey.trim().length === 0) {
    return { status: 400, reason: "denied_public_key", message: "public_key is required" };
  }

  if (typeof input.keyId !== "string" || input.keyId.trim().length === 0) {
    return { status: 400, reason: "denied_key_id", message: "key_id is required" };
  }
  const keyId = input.keyId.trim();
  if (keyId.length > SSH_CERT_MAX_KEY_ID_LENGTH) {
    return {
      status: 400,
      reason: "denied_key_id",
      message: `key_id exceeds ${SSH_CERT_MAX_KEY_ID_LENGTH} characters`,
    };
  }

  if (!Array.isArray(input.principals) || input.principals.length === 0) {
    return {
      status: 400,
      reason: "denied_principal",
      message: "principals must be a non-empty array",
    };
  }
  if (input.principals.length > SSH_CERT_MAX_PRINCIPALS) {
    return {
      status: 400,
      reason: "denied_principal",
      message: `principals exceeds the cap of ${SSH_CERT_MAX_PRINCIPALS}`,
    };
  }
  const principals: string[] = [];
  for (const p of input.principals) {
    if (typeof p !== "string" || p.trim().length === 0) {
      return {
        status: 400,
        reason: "denied_principal",
        message: "each principal must be a non-empty string",
      };
    }
    const principal = p.trim();
    if (!input.principalPattern.test(principal)) {
      return {
        status: 400,
        reason: "denied_principal",
        message: `principal ${JSON.stringify(principal)} does not match the allowed pattern`,
      };
    }
    principals.push(principal);
  }

  // extensions: default to permit-pty; reject anything not in the allowed
  // set. Critical options are never accepted from the caller at all (the
  // signer always stamps an empty critical-options block).
  let extensions: string[];
  if (input.extensions === undefined) {
    extensions = ["permit-pty"];
  } else if (!Array.isArray(input.extensions)) {
    return {
      status: 400,
      reason: "denied_extension",
      message: "extensions must be an array when provided",
    };
  } else {
    extensions = [];
    for (const e of input.extensions) {
      if (typeof e !== "string" || !SSH_CERT_ALLOWED_EXTENSIONS.has(e)) {
        return {
          status: 400,
          reason: "denied_extension",
          message: `extension ${JSON.stringify(e)} is not permitted; allowed: ${[...SSH_CERT_ALLOWED_EXTENSIONS].join(", ")}`,
        };
      }
      extensions.push(e);
    }
  }

  // ttl: default 10m; reject (don't clamp) anything outside [min, max].
  let ttlSeconds = SSH_CERT_DEFAULT_TTL_SECONDS;
  if (input.ttlSeconds !== undefined) {
    if (typeof input.ttlSeconds !== "number" || !Number.isFinite(input.ttlSeconds)) {
      return {
        status: 400,
        reason: "denied_ttl",
        message: "ttl_seconds must be a number",
      };
    }
    if (input.ttlSeconds < SSH_CERT_MIN_TTL_SECONDS) {
      return {
        status: 400,
        reason: "denied_ttl",
        message: `ttl_seconds below minimum (${SSH_CERT_MIN_TTL_SECONDS})`,
      };
    }
    if (input.ttlSeconds > SSH_CERT_MAX_TTL_SECONDS) {
      return {
        status: 400,
        reason: "denied_ttl",
        message: `ttl_seconds exceeds maximum (${SSH_CERT_MAX_TTL_SECONDS})`,
      };
    }
    ttlSeconds = Math.floor(input.ttlSeconds);
  }

  return { publicKey: input.publicKey.trim(), keyId, principals, extensions, ttlSeconds };
}

/** Compile the principal pattern from env, falling back to the default.
 *  A malformed env pattern throws at load time — fail closed rather than
 *  silently accept every principal. */
export function compilePrincipalPattern(raw: string | undefined): RegExp {
  const source = (raw ?? "").trim() || DEFAULT_PRINCIPAL_PATTERN;
  return new RegExp(source);
}
