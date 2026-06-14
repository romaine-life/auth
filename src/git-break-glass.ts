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

export type GitBreakGlassRepoScope =
  | { kind: "current_repo"; repo: string }
  | { kind: "repos"; repos: string[] }
  | { kind: "all_repos" };

export type GitBreakGlassBranchScope =
  | { kind: "named"; branches: string[] }
  | { kind: "count"; count: number }
  | { kind: "unlimited" };

export interface GitBreakGlassGrantRequest {
  sessionId: string;
  repoScope: GitBreakGlassRepoScope;
  branchScope: GitBreakGlassBranchScope;
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
    repo_scope: params.get("repo_scope") ?? "",
    branch_scope: params.get("branch_scope") ?? "",
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

  let repoScope: GitBreakGlassRepoScope;
  try {
    repoScope = normalizeRepoScope(parseObjectField(raw, "repo_scope", "repoScope"), stringField(raw, "repo"));
  } catch (err) {
    return { present: true, ok: false, error: err instanceof Error ? err.message : "repo_scope is invalid" };
  }

  const legacyRepo = stringField(raw, "repo").trim();
  let branchScope: GitBreakGlassBranchScope;
  try {
    branchScope = normalizeBranchScope(parseObjectField(raw, "branch_scope", "branchScope"), legacyRepo);
  } catch (err) {
    return { present: true, ok: false, error: err instanceof Error ? err.message : "branch_scope is invalid" };
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
    repoScope,
    branchScope,
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
      repo_scope: input.repoScope,
      branch_scope: input.branchScope,
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

export function gitBreakGlassRepoScopeLabel(scope: GitBreakGlassRepoScope): string {
  switch (scope.kind) {
    case "current_repo":
      return scope.repo;
    case "repos":
      return scope.repos.join(", ");
    case "all_repos":
      return "all repositories";
  }
}

export function gitBreakGlassBranchScopeLabel(scope: GitBreakGlassBranchScope): string {
  switch (scope.kind) {
    case "named":
      return scope.branches.join(", ");
    case "count":
      return `${scope.count} branch${scope.count === 1 ? "" : "es"}`;
    case "unlimited":
      return "unlimited branches";
  }
}

function stringField(raw: Record<string, unknown>, ...names: string[]): string {
  for (const name of names) {
    const value = raw[name];
    if (typeof value === "string") return value;
  }
  return "";
}

function parseObjectField(raw: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    const value = raw[name];
    if (value === undefined || value === null || value === "") continue;
    if (typeof value !== "string") return value;
    try {
      return JSON.parse(value);
    } catch {
      throw new Error(`${name} must be a JSON object`);
    }
  }
  return undefined;
}

function normalizeRepoScope(value: unknown, legacyRepo: string): GitBreakGlassRepoScope {
  if (value === undefined) {
    return normalizeRepoScope({ kind: "current_repo", repo: legacyRepo }, "");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("repo_scope is required");
  }
  const raw = value as Record<string, unknown>;
  const kind = stringField(raw, "kind").trim();
  switch (kind) {
    case "current_repo": {
      if (hasNonEmptyArray(raw.repos)) throw new Error("repo_scope current_repo rejects repos");
      const repo = normalizeGitHubRepoSlug(raw.repo);
      if (!repo) throw new Error("repo_scope current_repo requires repo");
      return { kind, repo };
    }
    case "repos": {
      if (stringFromUnknown(raw.repo).trim()) throw new Error("repo_scope repos rejects repo");
      const repos = normalizeGitHubRepoList(raw.repos);
      if (repos.length === 0) throw new Error("repo_scope repos requires at least one repo");
      return { kind, repos };
    }
    case "all_repos":
      if (stringFromUnknown(raw.repo).trim() || hasNonEmptyArray(raw.repos)) {
        throw new Error("repo_scope all_repos rejects repo and repos");
      }
      return { kind };
    default:
      throw new Error("repo_scope.kind must be current_repo, repos, or all_repos");
  }
}

function normalizeBranchScope(value: unknown, legacyRepo: string): GitBreakGlassBranchScope {
  if (value === undefined && legacyRepo) {
    return { kind: "unlimited" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("branch_scope is required");
  }
  const raw = value as Record<string, unknown>;
  const kind = stringField(raw, "kind").trim();
  const branchesRaw = raw.branches ?? [];
  const countRaw = raw.count;
  switch (kind) {
    case "named": {
      if (countRaw !== undefined && countRaw !== null && countRaw !== "" && countRaw !== 0) {
        throw new Error("branch_scope named rejects count");
      }
      const branches = normalizeBranchList(branchesRaw);
      if (branches.length === 0) throw new Error("branch_scope named requires branches");
      return { kind, branches };
    }
    case "count": {
      if (hasNonEmptyArray(branchesRaw)) throw new Error("branch_scope count rejects branches");
      const count = parsePositiveInteger(countRaw);
      if (count <= 0) throw new Error("branch_scope count requires a positive count");
      return { kind, count: Math.min(count, 50) };
    }
    case "unlimited":
      if (hasNonEmptyArray(branchesRaw) || (countRaw !== undefined && countRaw !== null && countRaw !== "" && countRaw !== 0)) {
        throw new Error("branch_scope unlimited rejects branches and count");
      }
      return { kind };
    default:
      throw new Error("branch_scope.kind must be named, count, or unlimited");
  }
}

function normalizeGitHubRepoList(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("repo_scope.repos must be an array of GitHub slugs");
  const out: string[] = [];
  for (const item of value) {
    const repo = normalizeGitHubRepoSlug(item);
    if (repo && !out.includes(repo)) out.push(repo);
  }
  return out;
}

function normalizeGitHubRepoSlug(value: unknown): string {
  const repo = stringFromUnknown(value).trim();
  if (!repo) return "";
  if (!GITHUB_REPO_PATTERN.test(repo)) {
    throw new Error("repo values must be GitHub slugs like owner/name");
  }
  return repo;
}

function normalizeBranchList(value: unknown): string[] {
  const values = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  const out: string[] = [];
  for (const item of values) {
    const branch = normalizeBranchName(item);
    if (branch && !out.includes(branch)) out.push(branch);
  }
  return out;
}

function normalizeBranchName(value: unknown): string {
  let raw = stringFromUnknown(value).trim();
  if (raw.startsWith("refs/heads/")) raw = raw.slice("refs/heads/".length);
  if (raw.includes("/")) raw = raw.slice(raw.lastIndexOf("/") + 1);
  return raw.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[._-]+|[._-]+$/g, "");
}

function hasNonEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function stringFromUnknown(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function parsePositiveInteger(value: unknown): number {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^[0-9]+$/.test(value.trim())) return Number(value.trim());
  return -1;
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
