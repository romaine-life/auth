// A human enrolls a machine credential once. Device assertions mint credentials
// for that machine's own account; they never renew a human sign-in. OpenBao keeps
// its established federation subject, while SSH and OpenProject exchanges require
// the assertion to bind the exact request. Route handlers supply the lookup and clock.
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";

/** Where a device posts its assertion; the assertion's `aud` must be exactly this. */
export const DEVICE_TOKEN_URL = "https://auth.romaine.life/api/auth/device/token";

/** An assertion lives at most this long (exp - iat), so a captured one is soon useless. */
export const ASSERTION_MAX_LIFETIME_SECONDS = 5 * 60;

/** Clock skew allowed on a device's iat/exp. */
export const ASSERTION_CLOCK_TOLERANCE_SECONDS = 30;

/** Registration needs a sign-in this recent, so a leaked day-old token can't register a
 *  permanent device. */
export const ENROLL_MAX_TOKEN_AGE_SECONDS = 10 * 60;

/** Third parties a device may ask a token for, and that token's lifetime. Declared in
 *  code, like the OAuth clients, so which services trust a device is reviewed. */
export const DEVICE_AUDIENCES: Record<string, { ttlSeconds: number }> = {
  machine: { ttlSeconds: 15 * 60 },
  // OpenBao, the home secret store (nelsong6/openbao): its jwt auth method binds each
  // role to one device's subject.
  openbao: { ttlSeconds: 5 * 60 },
  openproject: { ttlSeconds: 2 * 60 * 60 },
  ssh: { ttlSeconds: 10 * 60 },
};

/** Device names: what the machine is called at home (nelsonpc, treadmill, nas). */
const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;

export type DeviceErrorReason =
  | "invalid_request"
  | "device_not_registered"
  | "device_revoked"
  | "invalid_assertion"
  | "assertion_replayed"
  | "audience_not_allowed"
  | "account_not_approved"
  | "access_denied";

/** A refusal the client can act on: `reason` is machine-readable and distinct for "not
 *  registered" and "revoked", so the menu can say which. */
export class DeviceError extends Error {
  constructor(
    readonly reason: DeviceErrorReason,
    readonly status: 400 | 401 | 403,
    message: string,
  ) {
    super(message);
  }
}

export interface EnrollRequest {
  name: string;
  publicKeyJwk: JWK;
}

/** Validate an enroll body: a name and the PUBLIC half of an EC P-256 key. A JWK that
 *  carries a private part is refused, so a client bug can't send its key here. */
export function parseEnrollRequest(body: Record<string, unknown>): EnrollRequest {
  const name = body.name;
  if (typeof name !== "string" || !NAME.test(name)) {
    throw new DeviceError("invalid_request", 400, "name must be lowercase letters, digits and dashes");
  }
  const jwk = body.public_key_jwk;
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new DeviceError("invalid_request", 400, "public_key_jwk is required");
  }
  const k = jwk as Record<string, unknown>;
  if ("d" in k) {
    throw new DeviceError("invalid_request", 400, "public_key_jwk must not contain a private key");
  }
  if (k.kty !== "EC" || k.crv !== "P-256" || typeof k.x !== "string" || typeof k.y !== "string") {
    throw new DeviceError("invalid_request", 400, "public_key_jwk must be an EC P-256 public key");
  }
  return { name, publicKeyJwk: { kty: "EC", crv: "P-256", x: k.x, y: k.y } };
}

/** Whether a verified user token may register a device: a human role, minted in the
 *  last ENROLL_MAX_TOKEN_AGE_SECONDS, and not itself minted for a device or a bot (a
 *  device that could register more devices would make one stolen key permanent). */
export function checkEnrollToken(payload: Record<string, unknown>, now: number): string | null {
  if (payload.role !== "admin" && payload.role !== "user") return "a signed-in user's token is required";
  if (typeof payload.device === "string") return "a device's token can't register a device";
  if (payload.purpose === "bot") return "a bot token can't register a device";
  const iat = typeof payload.iat === "number" ? payload.iat : 0;
  if (now - iat > ENROLL_MAX_TOKEN_AGE_SECONDS) return "sign in again: registering a device needs a sign-in from the last 10 minutes";
  return null;
}

/** The federation subject for a device token: unique per user and device, stable across
 *  re-keying, so a third party's policy binds to one machine of one person. */
export function deviceSubject(userId: string, deviceName: string): string {
  return `device:${userId}/${deviceName}`;
}

export interface StoredDevice {
  id: string;
  userId: string;
  name: string;
  publicKeyJwk: JWK;
  revokedAt: Date | null;
}

export interface VerifyDeps {
  findDevice(id: string): Promise<StoredDevice | null>;
  /** Records a jti until it expires; returns false if it was already recorded. */
  claimJti(jti: string, expiresAt: number): boolean;
  now(): number;
  requestHash?: string;
}

/** Verify a device's assertion: an ES256 JWT whose header `kid` is the device id, with
 *  iss = sub = that id, aud = DEVICE_TOKEN_URL, a short lifetime and a fresh jti. */
export async function verifyDeviceAssertion(assertion: unknown, deps: VerifyDeps): Promise<StoredDevice> {
  if (typeof assertion !== "string" || assertion.split(".").length !== 3) {
    throw new DeviceError("invalid_request", 400, "assertion must be a signed JWT");
  }
  let kid: string | undefined;
  let alg: string | undefined;
  try {
    ({ kid, alg } = decodeProtectedHeader(assertion));
  } catch {
    throw new DeviceError("invalid_assertion", 401, "assertion header is unreadable");
  }
  if (alg !== "ES256") throw new DeviceError("invalid_assertion", 401, "assertion must be signed ES256");
  if (typeof kid !== "string" || !kid) throw new DeviceError("invalid_assertion", 401, "assertion header has no kid");

  const device = await deps.findDevice(kid);
  if (!device) throw new DeviceError("device_not_registered", 401, "this device isn't registered");
  if (device.revokedAt) throw new DeviceError("device_revoked", 401, "this device's registration was revoked");

  const now = deps.now();
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(device.publicKeyJwk, "ES256");
    ({ payload } = await jwtVerify(assertion, key, {
      algorithms: ["ES256"],
      audience: DEVICE_TOKEN_URL,
      issuer: device.id,
      subject: device.id,
      clockTolerance: ASSERTION_CLOCK_TOLERANCE_SECONDS,
      currentDate: new Date(now * 1000),
      requiredClaims: ["iat", "exp", "jti", ...(deps.requestHash ? ["request_hash"] : [])],
    }));
  } catch (e) {
    throw new DeviceError("invalid_assertion", 401, `assertion rejected: ${(e as Error).message}`);
  }
  const iat = payload.iat as number;
  const exp = payload.exp as number;
  if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp <= iat || iat > now + ASSERTION_CLOCK_TOLERANCE_SECONDS || exp - iat > ASSERTION_MAX_LIFETIME_SECONDS) {
    throw new DeviceError("invalid_assertion", 401, `assertion lifetime exceeds ${ASSERTION_MAX_LIFETIME_SECONDS}s`);
  }
  if (deps.requestHash && payload.request_hash !== deps.requestHash) {
    throw new DeviceError("invalid_assertion", 401, "assertion does not authorize this request");
  }
  if (typeof payload.jti !== "string" || !payload.jti || !deps.claimJti(payload.jti, exp)) {
    throw new DeviceError("assertion_replayed", 401, "assertion was already used");
  }
  return device;
}

/** The requested audience, checked against DEVICE_AUDIENCES; null means a machine token. */
export function resolveAudience(raw: unknown): { audience: string; ttlSeconds: number } | null {
  if (raw === undefined || raw === null || raw === "") return null;
  if (typeof raw !== "string" || !Object.hasOwn(DEVICE_AUDIENCES, raw)) {
    throw new DeviceError("audience_not_allowed", 400, `audience ${JSON.stringify(raw)} isn't one a device can ask for`);
  }
  return { audience: raw, ttlSeconds: DEVICE_AUDIENCES[raw].ttlSeconds };
}

/** An in-memory jti store. auth runs one replica, and an assertion lives five minutes, so
 *  a restart forgets only jtis that are about to expire anyway. */
export function createJtiStore(now: () => number) {
  const seen = new Map<string, number>();
  return (jti: string, expiresAt: number): boolean => {
    const t = now();
    for (const [k, e] of seen) if (e + ASSERTION_CLOCK_TOLERANCE_SECONDS < t) seen.delete(k);
    if (seen.has(jti)) return false;
    seen.set(jti, expiresAt);
    return true;
  };
}
