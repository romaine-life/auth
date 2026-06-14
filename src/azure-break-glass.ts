// Azure break-glass admin approval — the sibling of git-break-glass.ts for the
// azure-personal MCP. Azure access is session-scoped and all-or-nothing (the
// whole MCP is gated), so there is no repo/branch scope here; the approval just
// carries the session, a reason, and a TTL. Shared Tank-URL routing is reused
// from git-break-glass.ts.

import { buildTankOperatorInternalURL } from "./git-break-glass.js";

export { buildTankOperatorInternalURL };

export const AZURE_BREAK_GLASS_INTENT = "azure-break-glass";
export const AZURE_BREAK_GLASS_TTL_SECONDS = 3600;
export const AZURE_BREAK_GLASS_OPERATIONS = ["use_azure_personal_mcp"] as const;

export type AzureBreakGlassOperation = (typeof AZURE_BREAK_GLASS_OPERATIONS)[number];

const SESSION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const SESSION_SCOPE_PATTERN = /^tank-operator-slot-[1-9][0-9]*$/;
const REQUEST_EVENT_ID_PATTERN = /^[A-Za-z0-9._:-]{0,200}$/;

export interface AzureBreakGlassGrantRequest {
  sessionId: string;
  sessionScope: string;
  reason: string;
  requestEventId: string;
  operations: AzureBreakGlassOperation[];
  ttlSeconds: number;
}

export type AzureBreakGlassIntent =
  | { present: false }
  | ({ present: true; ok: true } & AzureBreakGlassGrantRequest)
  | { present: true; ok: false; error: string };

export class AzureBreakGlassApprovalError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly upstreamBody: unknown,
  ) {
    super(message);
    this.name = "AzureBreakGlassApprovalError";
  }
}

export function parseAzureBreakGlassIntent(params: URLSearchParams): AzureBreakGlassIntent {
  const intent = params.get("intent")?.trim() ?? "";
  if (intent !== AZURE_BREAK_GLASS_INTENT) return { present: false };
  return parseAzureBreakGlassGrantRequest({
    session_id: params.get("session_id") ?? "",
    session_scope: params.get("session_scope") ?? "",
    reason: params.get("reason") ?? "",
    request_event_id: params.get("request_event_id") ?? "",
    operations: params.getAll("operation"),
    ttl_seconds: params.get("ttl_seconds") ?? "",
  });
}

export function parseAzureBreakGlassGrantRequest(input: unknown): AzureBreakGlassIntent {
  if (!input || typeof input !== "object") {
    return { present: true, ok: false, error: "request body must be an object" };
  }
  const raw = input as Record<string, unknown>;
  const sessionId = stringField(raw, "session_id", "sessionId").trim();
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return { present: true, ok: false, error: "session_id is required" };
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
    sessionScope,
    reason: clampReason(stringField(raw, "reason")),
    requestEventId,
    operations: normalizeAzureBreakGlassOperations(raw.operations),
    ttlSeconds,
  };
}

export function buildTankAzureBreakGlassGrantURL(baseURL: string, sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    throw new Error("session_id is required");
  }
  const base = baseURL.replace(/\/+$/, "");
  return `${base}/api/internal/sessions/${encodeURIComponent(sessionId)}/azure-break-glass/grants`;
}

export interface ApproveAzureBreakGlassGrantInput extends AzureBreakGlassGrantRequest {
  tankOperatorInternalURL: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
}

export async function approveAzureBreakGlassGrant(
  input: ApproveAzureBreakGlassGrantInput,
): Promise<unknown> {
  const fetcher = input.fetchImpl ?? fetch;
  const res = await fetcher(buildTankAzureBreakGlassGrantURL(input.tankOperatorInternalURL, input.sessionId), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${input.serviceToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      ttl_seconds: input.ttlSeconds,
      operations: input.operations,
      request_event_id: input.requestEventId,
      reason: input.reason,
    }),
  });
  const body = await responseBody(res);
  if (!res.ok) {
    throw new AzureBreakGlassApprovalError(
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
    return AZURE_BREAK_GLASS_TTL_SECONDS;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value.trim())) {
    return Number(value.trim());
  }
  return -1;
}

function normalizeAzureBreakGlassOperations(value: unknown): AzureBreakGlassOperation[] {
  const input = Array.isArray(value) ? value : [];
  const allowed = new Set<string>(AZURE_BREAK_GLASS_OPERATIONS);
  const out: AzureBreakGlassOperation[] = [];
  for (const item of input) {
    if (typeof item !== "string" || !allowed.has(item)) continue;
    if (!out.includes(item as AzureBreakGlassOperation)) {
      out.push(item as AzureBreakGlassOperation);
    }
  }
  return out.length > 0 ? out : [...AZURE_BREAK_GLASS_OPERATIONS];
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
