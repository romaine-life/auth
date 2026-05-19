import crypto from "node:crypto";

export const CLI_DEVICE_EXPIRES_SECONDS = 10 * 60;
export const CLI_DEVICE_POLL_INTERVAL_SECONDS = 5;

const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export type CliDeviceStatus =
  | "pending"
  | "approved"
  | "consumed"
  | "denied"
  | "expired";

export function randomUrlToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function generateUserCode(): string {
  let code = "";
  for (let i = 0; i < 8; i += 1) {
    code += USER_CODE_ALPHABET[crypto.randomInt(USER_CODE_ALPHABET.length)];
  }
  return `VK-${code.slice(0, 4)}-${code.slice(4)}`;
}

export function normalizeUserCode(input: string): string {
  return input.trim().toUpperCase().replace(/[\s-]+/g, "");
}

export function hashSecret(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("base64url");
}

export function requireSelfIdentification(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("self_identification is required");
  }
  const trimmed = value.replace(/\s+/g, " ").trim();
  if (!trimmed) {
    throw new Error("self_identification is required");
  }
  return trimmed.slice(0, 500);
}

export function validateLoopbackRedirectUri(value: unknown): string | null {
  if (value == null || value === "") return null;
  if (typeof value !== "string") {
    throw new Error("redirect_uri must be a string");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("redirect_uri must be an absolute URL");
  }

  if (url.protocol !== "http:") {
    throw new Error("redirect_uri must use http");
  }
  if (url.username || url.password) {
    throw new Error("redirect_uri must not contain credentials");
  }
  if (!url.port) {
    throw new Error("redirect_uri must include an explicit port");
  }

  const host = url.hostname.toLowerCase();
  if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]" && host !== "::1") {
    throw new Error("redirect_uri must target localhost, 127.0.0.1, or ::1");
  }

  return url.toString();
}

export function validatePkceInput(
  redirectUri: string | null,
  codeChallenge: unknown,
  codeChallengeMethod: unknown,
): { codeChallenge: string | null; codeChallengeMethod: "S256" | null } {
  if (codeChallenge == null || codeChallenge === "") {
    if (redirectUri) {
      throw new Error("code_challenge is required when redirect_uri is set");
    }
    return { codeChallenge: null, codeChallengeMethod: null };
  }
  if (typeof codeChallenge !== "string") {
    throw new Error("code_challenge must be a string");
  }
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
    throw new Error("code_challenge must be base64url text, 43-128 characters");
  }

  const method = codeChallengeMethod == null || codeChallengeMethod === ""
    ? "S256"
    : codeChallengeMethod;
  if (method !== "S256") {
    throw new Error("only code_challenge_method=S256 is supported");
  }

  return { codeChallenge, codeChallengeMethod: "S256" };
}

export function verifyPkceS256(codeVerifier: unknown, codeChallenge: string): boolean {
  if (typeof codeVerifier !== "string") return false;
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) return false;
  const expected = hashSecret(codeVerifier);
  const expectedBytes = Buffer.from(expected);
  const challengeBytes = Buffer.from(codeChallenge);
  if (expectedBytes.length !== challengeBytes.length) return false;
  return crypto.timingSafeEqual(expectedBytes, challengeBytes);
}

export function appendCallbackParams(
  redirectUri: string,
  code: string,
  state: string | null,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}
