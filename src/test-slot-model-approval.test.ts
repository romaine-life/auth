import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TestSlotModelApprovalError,
  approveTestSlotModelApproval,
  buildTankOperatorInternalURL,
  buildTankTestSlotModelApprovalGrantURL,
  parseTestSlotModelApprovalGrantRequest,
  parseTestSlotModelApprovalIntent,
} from "./test-slot-model-approval.js";

test("parseTestSlotModelApprovalIntent ignores unrelated admin visits", () => {
  assert.deepStrictEqual(
    parseTestSlotModelApprovalIntent(new URLSearchParams("intent=azure-break-glass&session_id=47")),
    { present: false },
  );
  assert.deepStrictEqual(parseTestSlotModelApprovalIntent(new URLSearchParams("ok=updated")), {
    present: false,
  });
});

test("parseTestSlotModelApprovalIntent validates and defaults the approval request", () => {
  const parsed = parseTestSlotModelApprovalIntent(
    new URLSearchParams({
      intent: "test-slot-model",
      session_id: "941",
      session_scope: "tank-operator-slot-2",
      mode: "claude_gui",
      provider: "claude",
      model: "claude-opus-4-8",
      effort: "high",
      low_model: "claude-haiku-4-5",
      low_effort: "low",
      reason: "deep validation",
      request_event_id: "req-1",
    }),
  );
  assert.equal(parsed.present, true);
  if (!parsed.present || !parsed.ok) throw new Error("expected valid intent");
  assert.equal(parsed.sessionId, "941");
  assert.equal(parsed.sessionScope, "tank-operator-slot-2");
  assert.equal(parsed.mode, "claude_gui");
  assert.equal(parsed.provider, "claude");
  assert.equal(parsed.model, "claude-opus-4-8");
  assert.equal(parsed.effort, "high");
  assert.equal(parsed.lowModel, "claude-haiku-4-5");
  assert.equal(parsed.lowEffort, "low");
  assert.equal(parsed.reason, "deep validation");
  assert.equal(parsed.requestEventId, "req-1");
  assert.equal(parsed.ttlSeconds, 3600);
});

test("parseTestSlotModelApprovalGrantRequest rejects production and arbitrary scopes", () => {
  const base = {
    session_id: "941",
    mode: "codex_gui",
    model: "gpt-5.2",
    effort: "medium",
    low_model: "gpt-5.3-codex-spark",
    low_effort: "low",
  };
  const prod = parseTestSlotModelApprovalGrantRequest({
    ...base,
    session_scope: "default",
  });
  const arbitrary = parseTestSlotModelApprovalGrantRequest({
    ...base,
    session_scope: "http://metadata.google.internal",
  });
  assert.equal(prod.present && prod.ok, false);
  assert.equal(arbitrary.present && arbitrary.ok, false);
});

test("parseTestSlotModelApprovalGrantRequest rejects low-cost baseline requests", () => {
  const parsed = parseTestSlotModelApprovalGrantRequest({
    session_id: "941",
    session_scope: "tank-operator-slot-1",
    mode: "codex_gui",
    model: "gpt-5.3-codex-spark",
    effort: "low",
    low_model: "gpt-5.3-codex-spark",
    low_effort: "low",
  });
  assert.equal(parsed.present, true);
  assert.equal(parsed.ok, false);
});

test("parseTestSlotModelApprovalGrantRequest rejects out-of-range ttl", () => {
  const base = {
    session_id: "941",
    session_scope: "tank-operator-slot-1",
    mode: "claude_gui",
    model: "claude-opus-4-8",
    effort: "high",
    low_model: "claude-haiku-4-5",
    low_effort: "low",
  };
  const tooLong = parseTestSlotModelApprovalGrantRequest({ ...base, ttl_seconds: 999999 });
  const zero = parseTestSlotModelApprovalGrantRequest({ ...base, ttl_seconds: 0 });
  assert.equal(tooLong.present && tooLong.ok, false);
  assert.equal(zero.present && zero.ok, false);
});

test("buildTankTestSlotModelApprovalGrantURL builds the session grant URL", () => {
  assert.equal(
    buildTankTestSlotModelApprovalGrantURL(
      "http://tank-operator.tank-operator-slot-2.svc.cluster.local/",
      "941",
    ),
    "http://tank-operator.tank-operator-slot-2.svc.cluster.local/api/internal/sessions/941/test-slot-model-approvals/grants",
  );
  assert.throws(() => buildTankTestSlotModelApprovalGrantURL("http://x", "bad session!"));
});

test("buildTankOperatorInternalURL routes slot scopes to the slot service", () => {
  assert.equal(
    buildTankOperatorInternalURL(undefined, "tank-operator-slot-3"),
    "http://tank-operator.tank-operator-slot-3.svc.cluster.local",
  );
});

test("approveTestSlotModelApproval posts the grant body and returns the tank response", async () => {
  let captured: { url: string; init: RequestInit } | null = null;
  const fakeFetch = (async (url: string | URL, init?: RequestInit) => {
    captured = { url: String(url), init: init ?? {} };
    return new Response(
      JSON.stringify({
        active: true,
        event_id: "g1",
        session_id: "941",
        model: "claude-opus-4-8",
        effort: "high",
      }),
      {
        status: 201,
        headers: { "content-type": "application/json" },
      },
    );
  }) as unknown as typeof fetch;

  const out = await approveTestSlotModelApproval({
    sessionId: "941",
    sessionScope: "tank-operator-slot-2",
    mode: "claude_gui",
    provider: "claude",
    model: "claude-opus-4-8",
    effort: "high",
    lowModel: "claude-haiku-4-5",
    lowEffort: "low",
    reason: "deep validation",
    requestEventId: "req-1",
    ttlSeconds: 900,
    tankOperatorInternalURL: "http://tank-operator.tank-operator-slot-2.svc.cluster.local",
    serviceToken: "svc-token",
    fetchImpl: fakeFetch,
  });

  assert.deepStrictEqual(out, {
    active: true,
    event_id: "g1",
    session_id: "941",
    model: "claude-opus-4-8",
    effort: "high",
  });
  assert.ok(captured);
  const got = captured as { url: string; init: RequestInit };
  assert.equal(
    got.url,
    "http://tank-operator.tank-operator-slot-2.svc.cluster.local/api/internal/sessions/941/test-slot-model-approvals/grants",
  );
  assert.equal((got.init.headers as Record<string, string>).Authorization, "Bearer svc-token");
  const sent = JSON.parse(String(got.init.body));
  assert.equal(sent.mode, "claude_gui");
  assert.equal(sent.model, "claude-opus-4-8");
  assert.equal(sent.effort, "high");
  assert.equal(sent.ttl_seconds, 900);
  assert.equal(sent.request_event_id, "req-1");
  assert.equal(sent.reason, "deep validation");
  assert.equal(sent.low_model, undefined);
});

test("approveTestSlotModelApproval throws TestSlotModelApprovalError on non-2xx", async () => {
  const fakeFetch = (async () =>
    new Response(JSON.stringify({ error: "nope" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;

  await assert.rejects(
    () =>
      approveTestSlotModelApproval({
        sessionId: "941",
        sessionScope: "tank-operator-slot-2",
        mode: "claude_gui",
        provider: "claude",
        model: "claude-opus-4-8",
        effort: "high",
        lowModel: "claude-haiku-4-5",
        lowEffort: "low",
        reason: "",
        requestEventId: "",
        ttlSeconds: 900,
        tankOperatorInternalURL: "http://x",
        serviceToken: "t",
        fetchImpl: fakeFetch,
      }),
    (e: unknown) =>
      e instanceof TestSlotModelApprovalError &&
      (e as TestSlotModelApprovalError).status === 403,
  );
});
