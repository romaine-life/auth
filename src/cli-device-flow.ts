import crypto from "node:crypto";

export const CLI_DEVICE_EXPIRES_SECONDS = 10 * 60;
export const CLI_DEVICE_POLL_INTERVAL_SECONDS = 5;
export const CLI_WHERE_HAPPENING_MAX_LENGTH = 500;
export const CLI_INTENDED_USE_MAX_LENGTH = 500;
export const CLI_MISC_IDENTIFIER_MAX_LENGTH = 80;
export const CLI_PREVIOUS_MISC_IDENTIFIERS_LIMIT = 50;
export const CLI_ENVIRONMENT_NAME_MAX_LENGTH = 63;

const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export const CLI_APPROVAL_INPUT_DEFINITIONS = {
  environment_name: {
    label: "Environment name",
    description:
      "Choose the non-secret DNS-safe name the requesting development environment will use.",
    placeholder: "loading-feature",
    max_length: CLI_ENVIRONMENT_NAME_MAX_LENGTH,
  },
} as const;

export type CliApprovalInputName = keyof typeof CLI_APPROVAL_INPUT_DEFINITIONS;
export type CliApprovalValues = Partial<Record<CliApprovalInputName, string>>;

export type CliDeviceStatus =
  | "pending"
  | "approved"
  | "consumed"
  | "denied"
  | "expired";

export interface CliRequesterInfo {
  whereHappening: string;
  intendedUse: string;
  miscIdentifier: string;
}

export interface CliGrantMetadata {
  requester: CliRequesterInfo;
  approvalInputs: CliApprovalInputName[];
  approvalValues: CliApprovalValues | null;
}

export interface CliRequesterGuidance {
  instructions: string;
  fields: {
    where_happening: string;
    intended_use: string;
    misc_identifier: string;
  };
  constraints: {
    where_happening_max_length: number;
    intended_use_max_length: number;
    misc_identifier_max_length: number;
    previous_misc_identifiers_limit: number;
  };
  supported_approval_inputs: typeof CLI_APPROVAL_INPUT_DEFINITIONS;
  previous_misc_identifiers: string[];
}

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

function requireRequestField(
  value: unknown,
  field: "where_happening" | "intended_use" | "misc_identifier",
  maxLength: number,
): string {
  if (typeof value !== "string") {
    throw new Error(`${field} is required`);
  }
  const trimmed = value.replace(/\s+/g, " ").trim();
  if (!trimmed) {
    throw new Error(`${field} is required`);
  }
  return trimmed.slice(0, maxLength);
}

export function requireRequesterInfo(body: Record<string, unknown>): CliRequesterInfo {
  return {
    whereHappening: requireRequestField(
      body.where_happening,
      "where_happening",
      CLI_WHERE_HAPPENING_MAX_LENGTH,
    ),
    intendedUse: requireRequestField(
      body.intended_use,
      "intended_use",
      CLI_INTENDED_USE_MAX_LENGTH,
    ),
    miscIdentifier: requireRequestField(
      body.misc_identifier,
      "misc_identifier",
      CLI_MISC_IDENTIFIER_MAX_LENGTH,
    ),
  };
}

export function parseApprovalInputs(value: unknown): CliApprovalInputName[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error("approval_inputs must be an array");
  }

  const inputs: CliApprovalInputName[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (
      typeof item !== "string"
      || !Object.hasOwn(CLI_APPROVAL_INPUT_DEFINITIONS, item)
    ) {
      throw new Error(`unsupported approval input: ${String(item)}`);
    }
    if (seen.has(item)) {
      throw new Error(`duplicate approval input: ${item}`);
    }
    seen.add(item);
    inputs.push(item as CliApprovalInputName);
  }
  return inputs;
}

export function normalizeEnvironmentName(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("environment_name is required");
  }
  let name = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
  if (name.length > CLI_ENVIRONMENT_NAME_MAX_LENGTH) {
    name = name.slice(0, CLI_ENVIRONMENT_NAME_MAX_LENGTH).replace(/-+$/g, "");
  }
  if (!name) {
    throw new Error("environment_name must contain at least one letter or number");
  }
  return name;
}

export function requireApprovalValues(
  requestedInputs: CliApprovalInputName[],
  values: unknown,
): CliApprovalValues {
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    if (requestedInputs.length === 0) return {};
    throw new Error("approval values are required");
  }

  const source = values as Record<string, unknown>;
  const approved: CliApprovalValues = {};
  for (const input of requestedInputs) {
    if (input === "environment_name") {
      approved.environment_name = normalizeEnvironmentName(source.environment_name);
    }
  }
  return approved;
}

export function encodeRequesterInfo(info: CliRequesterInfo): string {
  return JSON.stringify({
    v: 1,
    where_happening: info.whereHappening,
    intended_use: info.intendedUse,
    misc_identifier: info.miscIdentifier,
  });
}

export function decodeRequesterInfo(value: string): CliRequesterInfo {
  try {
    const parsed = JSON.parse(value) as {
      where_happening?: unknown;
      intended_use?: unknown;
      misc_identifier?: unknown;
    };
    return requireRequesterInfo(parsed as Record<string, unknown>);
  } catch {
    return {
      whereHappening: value,
      intendedUse: "legacy request",
      miscIdentifier: "legacy",
    };
  }
}

export function encodeCliGrantMetadata(
  requester: CliRequesterInfo,
  approvalInputs: CliApprovalInputName[],
  approvalValues: CliApprovalValues | null = null,
): string {
  return JSON.stringify({
    v: 2,
    where_happening: requester.whereHappening,
    intended_use: requester.intendedUse,
    misc_identifier: requester.miscIdentifier,
    approval_inputs: approvalInputs,
    ...(approvalValues ? { approval_values: approvalValues } : {}),
  });
}

export function decodeCliGrantMetadata(value: string): CliGrantMetadata {
  const requester = decodeRequesterInfo(value);
  let parsed: Record<string, unknown>;
  try {
    const candidate = JSON.parse(value) as unknown;
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      return { requester, approvalInputs: [], approvalValues: null };
    }
    parsed = candidate as Record<string, unknown>;
  } catch {
    return { requester, approvalInputs: [], approvalValues: null };
  }

  const approvalInputs = parseApprovalInputs(parsed.approval_inputs);
  const approvalValues = parsed.approval_values == null
    ? null
    : requireApprovalValues(approvalInputs, parsed.approval_values);
  return { requester, approvalInputs, approvalValues };
}

export function previousMiscIdentifiersFromClientNames(
  clientNames: string[],
  limit = CLI_PREVIOUS_MISC_IDENTIFIERS_LIMIT,
): string[] {
  const previous: string[] = [];
  const seen = new Set<string>();
  for (const clientName of clientNames) {
    const requester = decodeRequesterInfo(clientName);
    if (requester.intendedUse === "legacy request" && requester.miscIdentifier === "legacy") {
      continue;
    }
    const miscIdentifier = requester.miscIdentifier.replace(/\s+/g, " ").trim();
    if (!miscIdentifier) continue;
    const key = miscIdentifier.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    previous.push(miscIdentifier.slice(0, CLI_MISC_IDENTIFIER_MAX_LENGTH));
    if (previous.length >= limit) break;
  }
  return previous;
}

export function buildRequesterGuidance(previousMiscIdentifiers: string[]): CliRequesterGuidance {
  return {
    instructions: "Choose requester fields before calling POST /api/cli/device. The misc identifier is intentionally chosen by the requester; choose a fresh common concrete singular noun that is not listed in previous_misc_identifiers.",
    fields: {
      where_happening: "Describe where this request is happening, such as the current session, workspace, host, or tool context.",
      intended_use: "Describe what the bot token will be used for in this immediate request.",
      misc_identifier: "Choose one common concrete singular noun for human recognition. Avoid auth, software, repository, and computer words. Do not reuse any noun listed in previous_misc_identifiers.",
    },
    constraints: {
      where_happening_max_length: CLI_WHERE_HAPPENING_MAX_LENGTH,
      intended_use_max_length: CLI_INTENDED_USE_MAX_LENGTH,
      misc_identifier_max_length: CLI_MISC_IDENTIFIER_MAX_LENGTH,
      previous_misc_identifiers_limit: CLI_PREVIOUS_MISC_IDENTIFIERS_LIMIT,
    },
    supported_approval_inputs: CLI_APPROVAL_INPUT_DEFINITIONS,
    previous_misc_identifiers: previousMiscIdentifiers.slice(0, CLI_PREVIOUS_MISC_IDENTIFIERS_LIMIT),
  };
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
