import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AzureBreakGlassApprovalError,
  approveAzureBreakGlassGrant,
  buildTankAzureBreakGlassGrantURL,
  buildTankOperatorInternalURL,
  parseAzureBreakGlassGrantRequest,
  parseAzureBreakGlassIntent,
} from "./azure-break-glass.js";

test("parseAzureBreakGlassIntent ignores non-azure admin visits", () => {
  assert.deepStrictEqual(
    parseAzureBreakGlassIntent(new URLSearchParams("intent=git-break-glass&session_id=47")),
    { present: false },
  );
  assert.deepStrictEqual(parseAzureBreakGlassIntent(new URLSearchParams("ok=updated")), {
    present: false,
  });
});

test("parseAzureBreakGlassIntent validates and defaults the approval request", () => {
  const parsed = parseAzureBreakGlassIntent(
    new URLSearchParams({ intent: "azure-break-glass", session_id: "941", reason: "inspect ledger" }),
  );
  assert.equal(parsed.present, true);
  if (!parsed.present || !parsed.ok) throw new Error("expected valid intent");
  assert.equal(parsed.sessionId, "941");
  assert.equal(parsed.sessionScope, "default");
  assert.equal(parsed.reason, "inspect ledger");
  assert.equal(parsed.ttlSeconds, 3600);
  assert.deepStrictEqual(parsed.operations, ["use_azure_personal_mcp"]);
});

test("parseAzureBreakGlassIntent honors slot session scope and ttl", () => {
  const parsed = parseAzureBreakGlassIntent(
    new URLSearchParams(
      "intent=azure-break-glass&session_id=3&session_scope=tank-operator-slot-2&ttl_seconds=900",
    ),
  );
  assert.equal(parsed.present, true);
  if (!parsed.present || !parsed.ok) throw new Error("expected valid intent");
  assert.equal(parsed.sessionScope, "tank-operator-slot-2");
  assert.equal(parsed.ttlSeconds, 900);
});

test("parseAzureBreakGlassGrantRequest requires a session id", () => {
  const parsed = parseAzureBreakGlassGrantRequest({ reason: "x" });
  assert.equal(parsed.present, true);
  assert.equal(parsed.ok, false);
});

test("parseAzureBreakGlassGrantRequest rejects arbitrary session scopes", () => {
  const parsed = parseAzureBreakGlassGrantRequest({
    session_id: "941",
    session_scope: "http://metadata.google.internal",
  });
  assert.equal(parsed.present, true);
  assert.equal(parsed.ok, false);
});

test("parseAzureBreakGlassGrantRequest rejects out-of-range ttl", () => {
  const tooLong = parseAzureBreakGlassGrantRequest({ session_id: "941", ttl_seconds: 999999 });
  const zero = parseAzureBreakGlassGrantRequest({ session_id: "941", ttl_seconds: 0 });
  assert.equal(tooLong.present && tooLong.ok, false);
  assert.equal(zero.present && zero.ok, false);
});

test("buildTankAzureBreakGlassGrantURL builds the session grant URL", () => {
  assert.equal(
    buildTankAzureBreakGlassGrantURL("http://tank-operator.tank-operator.svc.cluster.local/", "941"),
    "http://tank-operator.tank-operator.svc.cluster.local/api/internal/sessions/941/azure-break-glass/grants",
  );
  assert.throws(() => buildTankAzureBreakGlassGrantURL("http://x", "bad session!"));
});

test("buildTankOperatorInternalURL routes slot scopes to the slot service", () => {
  assert.equal(
    buildTankOperatorInternalURL(undefined, "tank-operator-slot-3"),
    "http://tank-operator.tank-operator-slot-3.svc.cluster.local",
  );
});

test("approveAzureBreakGlassGrant posts the grant body and returns the tank response", async () => {
  let captured: { url: string; init: RequestInit } | null = null;
  const fakeFetch = (async (url: string | URL, init?: RequestInit) => {
    captured = { url: String(url), init: init ?? {} };
    return new Response(JSON.stringify({ active: true, event_id: "g1", session_id: "941" }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;

  const out = await approveAzureBreakGlassGrant({
    sessionId: "941",
    sessionScope: "default",
    reason: "inspect",
    requestEventId: "req-1",
    operations: ["use_azure_personal_mcp"],
    ttlSeconds: 900,
    tankOperatorInternalURL: "http://tank-operator.tank-operator.svc.cluster.local",
    serviceToken: "svc-token",
    fetchImpl: fakeFetch,
  });

  assert.deepStrictEqual(out, { active: true, event_id: "g1", session_id: "941" });
  assert.ok(captured);
  const got = captured as { url: string; init: RequestInit };
  assert.equal(
    got.url,
    "http://tank-operator.tank-operator.svc.cluster.local/api/internal/sessions/941/azure-break-glass/grants",
  );
  assert.equal((got.init.headers as Record<string, string>).Authorization, "Bearer svc-token");
  const sent = JSON.parse(String(got.init.body));
  assert.equal(sent.ttl_seconds, 900);
  assert.deepStrictEqual(sent.operations, ["use_azure_personal_mcp"]);
  assert.equal(sent.request_event_id, "req-1");
  assert.equal(sent.reason, "inspect");
  // azure grants are not repo-scoped — no repo/repo_scope/branch_scope in the body
  assert.equal(sent.repo, undefined);
  assert.equal(sent.repo_scope, undefined);
});

test("approveAzureBreakGlassGrant throws AzureBreakGlassApprovalError on non-2xx", async () => {
  const fakeFetch = (async () =>
    new Response(JSON.stringify({ error: "nope" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;

  await assert.rejects(
    () =>
      approveAzureBreakGlassGrant({
        sessionId: "941",
        sessionScope: "default",
        reason: "",
        requestEventId: "",
        operations: ["use_azure_personal_mcp"],
        ttlSeconds: 900,
        tankOperatorInternalURL: "http://x",
        serviceToken: "t",
        fetchImpl: fakeFetch,
      }),
    (e: unknown) =>
      e instanceof AzureBreakGlassApprovalError && (e as AzureBreakGlassApprovalError).status === 403,
  );
});
