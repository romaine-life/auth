import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_TANK_OPERATOR_INTERNAL_URL,
  GitBreakGlassApprovalError,
  approveGitBreakGlassGrant,
  buildTankGitBreakGlassGrantURL,
  buildTankOperatorInternalURL,
  parseGitBreakGlassGrantRequest,
  parseGitBreakGlassIntent,
} from "./git-break-glass.js";

test("parseGitBreakGlassIntent ignores non-break-glass admin visits", () => {
  assert.deepStrictEqual(parseGitBreakGlassIntent(new URLSearchParams("ok=updated")), {
    present: false,
  });
});

test("parseGitBreakGlassIntent validates and defaults the approval request", () => {
  const params = new URLSearchParams({
    intent: "git-break-glass",
    session_id: "47",
    repo_scope: JSON.stringify({ kind: "current_repo", repo: "romaine-life/tank-operator" }),
    branch_scope: JSON.stringify({ kind: "named", branches: ["refs/heads/repair"] }),
    reason: "need push",
  });
  const parsed = parseGitBreakGlassIntent(
    params,
  );
  assert.equal(parsed.present, true);
  if (!parsed.present || !parsed.ok) throw new Error("expected valid intent");
  assert.equal(parsed.sessionId, "47");
  assert.deepStrictEqual(parsed.repoScope, { kind: "current_repo", repo: "romaine-life/tank-operator" });
  assert.deepStrictEqual(parsed.branchScope, { kind: "named", branches: ["repair"] });
  assert.equal(parsed.sessionScope, "default");
  assert.equal(parsed.reason, "need push");
  assert.equal(parsed.ttlSeconds, 3600);
  assert.deepStrictEqual(parsed.operations, ["mint_full_git_token", "push_current_head"]);
});

test("parseGitBreakGlassIntent accepts legacy repo-only approval URLs as current repo unlimited", () => {
  const parsed = parseGitBreakGlassIntent(
    new URLSearchParams(
      "intent=git-break-glass&session_id=47&repo=romaine-life%2Ftank-operator&reason=need+push",
    ),
  );
  assert.equal(parsed.present, true);
  if (!parsed.present || !parsed.ok) throw new Error("expected valid intent");
  assert.deepStrictEqual(parsed.repoScope, { kind: "current_repo", repo: "romaine-life/tank-operator" });
  assert.deepStrictEqual(parsed.branchScope, { kind: "unlimited" });
});

test("parseGitBreakGlassGrantRequest rejects arbitrary session scopes", () => {
  const parsed = parseGitBreakGlassGrantRequest({
    session_id: "47",
    repo_scope: { kind: "current_repo", repo: "romaine-life/tank-operator" },
    branch_scope: { kind: "unlimited" },
    session_scope: "http://metadata.google.internal",
  });
  assert.equal(parsed.present, true);
  if (!parsed.present || parsed.ok) throw new Error("expected invalid request");
  assert.match(parsed.error, /session_scope/);
});

test("parseGitBreakGlassGrantRequest rejects conflicting scoped options", () => {
  const invalidRepo = parseGitBreakGlassGrantRequest({
    session_id: "47",
    repo_scope: { kind: "all_repos", repo: "romaine-life/tank-operator" },
    branch_scope: { kind: "unlimited" },
  });
  assert.equal(invalidRepo.present, true);
  if (!invalidRepo.present || invalidRepo.ok) throw new Error("expected invalid repo scope");
  assert.match(invalidRepo.error, /all_repos rejects repo/);

  const invalidBranch = parseGitBreakGlassGrantRequest({
    session_id: "47",
    repo_scope: { kind: "current_repo", repo: "romaine-life/tank-operator" },
    branch_scope: { kind: "unlimited", branches: ["docs"] },
  });
  assert.equal(invalidBranch.present, true);
  if (!invalidBranch.present || invalidBranch.ok) throw new Error("expected invalid branch scope");
  assert.match(invalidBranch.error, /unlimited rejects branches/);
});

test("buildTankOperatorInternalURL routes default and slot scopes without arbitrary URLs", () => {
  assert.equal(
    buildTankOperatorInternalURL(undefined, "default"),
    DEFAULT_TANK_OPERATOR_INTERNAL_URL,
  );
  assert.equal(
    buildTankOperatorInternalURL("http://tank.local///", "default"),
    "http://tank.local",
  );
  assert.equal(
    buildTankOperatorInternalURL("http://tank.local", "tank-operator-slot-6"),
    "http://tank-operator.tank-operator-slot-6.svc.cluster.local",
  );
});

test("buildTankGitBreakGlassGrantURL targets the session grant endpoint", () => {
  assert.equal(
    buildTankGitBreakGlassGrantURL("http://tank.local/", "session:47"),
    "http://tank.local/api/internal/sessions/session%3A47/git-break-glass/grants",
  );
});

test("approveGitBreakGlassGrant posts the bounded grant body to tank", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (url, init) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(JSON.stringify({ active: true, event_id: "grant-1" }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  };

  const body = await approveGitBreakGlassGrant({
    tankOperatorInternalURL: "http://tank.local",
    serviceToken: "service-token",
    sessionId: "47",
    repoScope: { kind: "repos", repos: ["romaine-life/tank-operator", "romaine-life/auth"] },
    branchScope: { kind: "count", count: 5 },
    sessionScope: "default",
    reason: "requested from auth",
    requestEventId: "request-1",
    operations: ["push_current_head"],
    ttlSeconds: 900,
    fetchImpl,
  });

  assert.deepStrictEqual(body, { active: true, event_id: "grant-1" });
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "http://tank.local/api/internal/sessions/47/git-break-glass/grants",
  );
  assert.equal((calls[0].init.headers as Record<string, string>).Authorization, "Bearer service-token");
  assert.deepStrictEqual(JSON.parse(String(calls[0].init.body)), {
    repo: "romaine-life/tank-operator",
    repo_scope: { kind: "repos", repos: ["romaine-life/tank-operator", "romaine-life/auth"] },
    branch_scope: { kind: "count", count: 5 },
    ttl_seconds: 900,
    operations: ["push_current_head"],
    request_event_id: "request-1",
    reason: "requested from auth",
  });
});

test("approveGitBreakGlassGrant surfaces tank errors", async () => {
  const fetchImpl: typeof fetch = async () =>
    new Response(JSON.stringify({ detail: "route requires role=service" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });

  await assert.rejects(
    () =>
      approveGitBreakGlassGrant({
        tankOperatorInternalURL: "http://tank.local",
        serviceToken: "bad-token",
        sessionId: "47",
        repoScope: { kind: "current_repo", repo: "romaine-life/tank-operator" },
        branchScope: { kind: "unlimited" },
        sessionScope: "default",
        reason: "",
        requestEventId: "",
        operations: ["mint_full_git_token"],
        ttlSeconds: 3600,
        fetchImpl,
      }),
    (err: unknown) =>
      err instanceof GitBreakGlassApprovalError &&
      err.status === 403 &&
      JSON.stringify(err.upstreamBody).includes("role=service"),
  );
});
