export const TEST_SLOT_MODEL_APPROVAL_INTENT = "test-slot-model";
export const TEST_SLOT_MODEL_APPROVAL_TTL_SECONDS = 3600;
export const DEFAULT_TANK_OPERATOR_INTERNAL_URL =
  "http://tank-operator.tank-operator.svc.cluster.local";

const SESSION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const SESSION_SCOPE_PATTERN = /^tank-operator-slot-[1-9][0-9]*$/;
const REQUEST_EVENT_ID_PATTERN = /^[A-Za-z0-9._:-]{0,200}$/;
const MODE_PATTERN = /^[A-Za-z0-9_:-]{1,80}$/;
const MODEL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const EFFORT_PATTERN = /^[A-Za-z0-9_:-]{1,32}$/;

export interface TestSlotModelApprovalGrantRequest {
  sessionId: string;
  sessionScope: string;
  mode: string;
  provider: string;
  model: string;
  effort: string;
  lowModel: string;
  lowEffort: string;
  reason: string;
  requestEventId: string;
  ttlSeconds: number;
}

export type TestSlotModelApprovalIntent =
  | { present: false }
  | ({ present: true; ok: true } & TestSlotModelApprovalGrantRequest)
  | { present: true; ok: false; error: string };

export class TestSlotModelApprovalError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly upstreamBody: unknown,
  ) {
    super(message);
    this.name = "TestSlotModelApprovalError";
  }
}

export function parseTestSlotModelApprovalIntent(params: URLSearchParams): TestSlotModelApprovalIntent {
  const intent = params.get("intent")?.trim() ?? "";
  if (intent !== TEST_SLOT_MODEL_APPROVAL_INTENT) return { present: false };
  return parseTestSlotModelApprovalGrantRequest({
    session_id: params.get("session_id") ?? "",
    session_scope: params.get("session_scope") ?? "",
    mode: params.get("mode") ?? "",
    provider: params.get("provider") ?? "",
    model: params.get("model") ?? "",
    effort: params.get("effort") ?? "",
    low_model: params.get("low_model") ?? "",
    low_effort: params.get("low_effort") ?? "",
    reason: params.get("reason") ?? "",
    request_event_id: params.get("request_event_id") ?? "",
    ttl_seconds: params.get("ttl_seconds") ?? "",
  });
}

export function parseTestSlotModelApprovalGrantRequest(input: unknown): TestSlotModelApprovalIntent {
  if (!input || typeof input !== "object") {
    return { present: true, ok: false, error: "request body must be an object" };
  }
  const raw = input as Record<string, unknown>;
  const sessionId = stringField(raw, "session_id", "sessionId").trim();
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return { present: true, ok: false, error: "session_id is required" };
  }

  const sessionScope = normalizeSessionScope(stringField(raw, "session_scope", "sessionScope"));
  if (!isAllowedSessionScope(sessionScope) || sessionScope === "default") {
    return {
      present: true,
      ok: false,
      error: "session_scope must be a tank-operator-slot-N test slot",
    };
  }

  const mode = stringField(raw, "mode").trim();
  if (!MODE_PATTERN.test(mode)) {
    return { present: true, ok: false, error: "mode is required" };
  }
  const model = stringField(raw, "model").trim();
  if (!MODEL_PATTERN.test(model)) {
    return { present: true, ok: false, error: "model is required" };
  }
  const effort = stringField(raw, "effort").trim();
  if (!EFFORT_PATTERN.test(effort)) {
    return { present: true, ok: false, error: "effort is required" };
  }
  const lowModel = stringField(raw, "low_model", "lowModel").trim();
  if (!MODEL_PATTERN.test(lowModel)) {
    return { present: true, ok: false, error: "low_model is required" };
  }
  const lowEffort = stringField(raw, "low_effort", "lowEffort").trim();
  if (!EFFORT_PATTERN.test(lowEffort)) {
    return { present: true, ok: false, error: "low_effort is required" };
  }
  if (model === lowModel && effort === lowEffort) {
    return {
      present: true,
      ok: false,
      error: "requested model and effort already match the low-cost test-slot baseline",
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
    mode,
    provider: stringField(raw, "provider").trim(),
    model,
    effort,
    lowModel,
    lowEffort,
    reason: clampReason(stringField(raw, "reason")),
    requestEventId,
    ttlSeconds,
  };
}

export function buildTankTestSlotModelApprovalGrantURL(baseURL: string, sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    throw new Error("session_id is required");
  }
  const base = baseURL.replace(/\/+$/, "");
  return `${base}/api/internal/sessions/${encodeURIComponent(sessionId)}/test-slot-model-approvals/grants`;
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

export interface ApproveTestSlotModelApprovalInput extends TestSlotModelApprovalGrantRequest {
  tankOperatorInternalURL: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
}

export async function approveTestSlotModelApproval(
  input: ApproveTestSlotModelApprovalInput,
): Promise<unknown> {
  const fetcher = input.fetchImpl ?? fetch;
  const res = await fetcher(buildTankTestSlotModelApprovalGrantURL(input.tankOperatorInternalURL, input.sessionId), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${input.serviceToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      mode: input.mode,
      model: input.model,
      effort: input.effort,
      request_event_id: input.requestEventId,
      reason: input.reason,
      ttl_seconds: input.ttlSeconds,
    }),
  });
  const body = await responseBody(res);
  if (!res.ok) {
    throw new TestSlotModelApprovalError(
      `tank-operator model approval request failed with HTTP ${res.status}`,
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
    return TEST_SLOT_MODEL_APPROVAL_TTL_SECONDS;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value.trim())) {
    return Number(value.trim());
  }
  return -1;
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
