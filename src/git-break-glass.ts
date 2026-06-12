export const GIT_BREAK_GLASS_INTENT = "git-break-glass";
export const GIT_BREAK_GLASS_TTL_SECONDS = 3600;
export const GIT_BREAK_GLASS_OPERATIONS = [
  "mint_full_git_token",
  "push_current_head",
] as const;

export type GitBreakGlassOperation = (typeof GIT_BREAK_GLASS_OPERATIONS)[number];

export const DEFAULT_TANK_OPERATOR_INTERNAL_URL =
  "http://tank-operator.tank-operator.svc.cluster.local";

const SESSION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const GITHUB_REPO_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const SESSION_SCOPE_PATTERN = /^tank-operator-slot-[1-9][0-9]*$/;
const REQUEST_EVENT_ID_PATTERN = /^[A-Za-z0-9._:-]{0,200}$/;

export interface GitBreakGlassGrantRequest {
  sessionId: string;
  repo: string;
  sessionScope: string;
  reason: string;
  requestEventId: string;
  operations: GitBreakGlassOperation[];
  ttlSeconds: number;
}

export type GitBreakGlassIntent =
  | { present: false }
  | ({ present: true; ok: true } & GitBreakGlassGrantRequest)
  | { present: true; ok: false; error: string };

export class GitBreakGlassApprovalError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly upstreamBody: unknown,
  ) {
    super(message);
    this.name = "GitBreakGlassApprovalError";
  }
}

export function parseGitBreakGlassIntent(params: URLSearchParams): GitBreakGlassIntent {
  const intent = params.get("intent")?.trim() ?? "";
  if (intent !== GIT_BREAK_GLASS_INTENT) return { present: false };
  return parseGitBreakGlassGrantRequest({
    session_id: params.get("session_id") ?? "",
    repo: params.get("repo") ?? "",
    session_scope: params.get("session_scope") ?? "",
    reason: params.get("reason") ?? "",
    request_event_id: params.get("request_event_id") ?? "",
    operations: params.getAll("operation"),
    ttl_seconds: params.get("ttl_seconds") ?? "",
  });
}

export function parseGitBreakGlassGrantRequest(input: unknown): GitBreakGlassIntent {
  if (!input || typeof input !== "object") {
    return { present: true, ok: false, error: "request body must be an object" };
  }
  const raw = input as Record<string, unknown>;
  const sessionId = stringField(raw, "session_id", "sessionId").trim();
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return { present: true, ok: false, error: "session_id is required" };
  }

  const repo = stringField(raw, "repo").trim();
  if (!GITHUB_REPO_PATTERN.test(repo)) {
    return {
      present: true,
      ok: false,
      error: "repo must be a GitHub slug like owner/name",
    };
  }

  const sessionScope = normalizeSessionScope(stringField(raw, "session_scope", "sessionScope"));
  if (!isAllowedSessionScope(sessionScope)) {
    return {
      present: true,
      ok: false,
      error: "session_scope must be default or tank-operator-slot-N",
    };
  }

  const requestEventId = stringField(raw, "request_event_id", "requestEventId").trim();
  if (!REQUEST_EVENT_ID_PATTERN.test(requestEventId)) {
    return { present: true, ok: false, error: "request_event_id is invalid" };
  }

  const ttlSeconds = parseTTLSeconds(raw);
  if (ttlSeconds <= 0 || ttlSeconds > 24 * 3600) {
    return { present: true, ok: false, error: "ttl_seconds must be between 1 and 86400" };
  }

  return {
    present: true,
    ok: true,
    sessionId,
    repo,
    sessionScope,
    reason: clampReason(stringField(raw, "reason")),
    requestEventId,
    operations: normalizeGitBreakGlassOperations(raw.operations),
    ttlSeconds,
  };
}

export function buildTankOperatorInternalURL(
  configuredURL: string | undefined,
  sessionScope: string,
): string {
  const scope = normalizeSessionScope(sessionScope);
  if (scope !== "default") {
    if (!isAllowedSessionScope(scope)) {
      throw new Error("session_scope must be default or tank-operator-slot-N");
    }
    return `http://tank-operator.${scope}.svc.cluster.local`;
  }
  const base = (configuredURL ?? DEFAULT_TANK_OPERATOR_INTERNAL_URL).trim();
  return base.replace(/\/+$/, "") || DEFAULT_TANK_OPERATOR_INTERNAL_URL;
}

export function buildTankGitBreakGlassGrantURL(baseURL: string, sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    throw new Error("session_id is required");
  }
  const base = baseURL.replace(/\/+$/, "");
  return `${base}/api/internal/sessions/${encodeURIComponent(sessionId)}/git-break-glass/grants`;
}

export interface ApproveGitBreakGlassGrantInput extends GitBreakGlassGrantRequest {
  tankOperatorInternalURL: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
}

export async function approveGitBreakGlassGrant(
  input: ApproveGitBreakGlassGrantInput,
): Promise<unknown> {
  const fetcher = input.fetchImpl ?? fetch;
  const res = await fetcher(buildTankGitBreakGlassGrantURL(input.tankOperatorInternalURL, input.sessionId), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${input.serviceToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      repo: input.repo,
      ttl_seconds: input.ttlSeconds,
      operations: input.operations,
      request_event_id: input.requestEventId,
      reason: input.reason,
    }),
  });
  const body = await responseBody(res);
  if (!res.ok) {
    throw new GitBreakGlassApprovalError(
      `tank-operator grant request failed with HTTP ${res.status}`,
      res.status,
      body,
    );
  }
  return body;
}

function stringField(raw: Record<string, unknown>, ...names: string[]): string {
  for (const name of names) {
    const value = raw[name];
    if (typeof value === "string") return value;
  }
  return "";
}

function normalizeSessionScope(value: string): string {
  const trimmed = value.trim();
  return trimmed === "" ? "default" : trimmed;
}

function isAllowedSessionScope(scope: string): boolean {
  return scope === "default" || SESSION_SCOPE_PATTERN.test(scope);
}

function parseTTLSeconds(raw: Record<string, unknown>): number {
  const value = raw.ttl_seconds ?? raw.ttlSeconds;
  if (value === undefined || value === null || value === "") {
    return GIT_BREAK_GLASS_TTL_SECONDS;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value.trim())) {
    return Number(value.trim());
  }
  return -1;
}

function normalizeGitBreakGlassOperations(value: unknown): GitBreakGlassOperation[] {
  const input = Array.isArray(value) ? value : [];
  const allowed = new Set<string>(GIT_BREAK_GLASS_OPERATIONS);
  const out: GitBreakGlassOperation[] = [];
  for (const item of input) {
    if (typeof item !== "string" || !allowed.has(item)) continue;
    if (!out.includes(item as GitBreakGlassOperation)) {
      out.push(item as GitBreakGlassOperation);
    }
  }
  return out.length > 0 ? out : [...GIT_BREAK_GLASS_OPERATIONS];
}

function clampReason(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 500) return trimmed;
  return trimmed.slice(0, 500);
}

async function responseBody(res: Response): Promise<unknown> {
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
  return await res.text();
}
