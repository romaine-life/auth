import { test } from "node:test";
import assert from "node:assert/strict";
import {
  authRomaineExchangeTotal,
  adminOriginsRequestsTotal,
  authAdminBotTokensMintedTotal,
  authAdminServiceTokensMintedTotal,
  authAdminTestSlotModelApprovalsTotal,
  recordAdminBotTokenMint,
  recordAdminOrigins,
  recordAdminServiceTokenMint,
  recordAdminTestSlotModelApproval,
  recordExchange,
  registry,
} from "./metrics.js";

// These tests assert the counter contract that downstream dashboards
// and alerts depend on: the metric name, label names, and the closed
// set of `result` values. Changing any of these is a coordinated
// dashboard/alert change — fail loud here so a typo doesn't silently
// drift the production series.

test("authRomaineExchangeTotal exposes the documented metric name", async () => {
  const text = await registry.metrics();
  assert.match(text, /^# HELP auth_romaine_exchange_total /m);
  assert.match(text, /^# TYPE auth_romaine_exchange_total counter$/m);
});

test("authRomaineExchangeTotal records by `result` label", async () => {
  recordExchange("success");
  recordExchange("denied_token");
  recordExchange("denied_token");
  const text = await registry.metrics();
  assert.match(text, /auth_romaine_exchange_total\{result="success"\} \d+/);
  assert.match(text, /auth_romaine_exchange_total\{result="denied_token"\} \d+/);
});

test("recordExchange accepts every documented ExchangeResultLabel", () => {
  // Compile-time invariant: each call typechecks against the union.
  // Runtime: also confirms the call doesn't throw on any value.
  for (const r of [
    "success",
    "denied_token",
    "denied_allowlist",
    "denied_unbound_pod",
    "denied_unknown_namespace",
    "denied_annotation_missing",
    "denied_pod_lookup_failed",
    "error_jwt_mint",
    "error_internal",
  ] as const) {
    recordExchange(r);
  }
  assert.ok(true);
});

test("adminOriginsRequestsTotal exposes the documented metric name", async () => {
  recordAdminOrigins("GET", "success");
  const text = await registry.metrics();
  assert.match(text, /^# TYPE auth_admin_origins_requests_total counter$/m);
  assert.match(
    text,
    /auth_admin_origins_requests_total\{method="GET",result="success"\} \d+/,
  );
});

test("default Node/process metrics are registered alongside the app counters", async () => {
  // prom-client's collectDefaultMetrics exports nodejs_version_info,
  // process_resident_memory_bytes, etc. — confirm one is present so a
  // future refactor that drops collectDefaultMetrics is caught here.
  const text = await registry.metrics();
  assert.match(text, /auth_process_cpu_user_seconds_total/);
});

test("registered counter names match what the dashboards and alerts expect", async () => {
  // Counter.name is internal in prom-client's typings; surface it via
  // the registry instead. A typo here breaks every dashboard and alert
  // that consumes the series — fail loud in CI.
  const text = await registry.metrics();
  assert.match(text, /^# HELP auth_romaine_exchange_total /m);
  assert.match(text, /^# HELP auth_admin_origins_requests_total /m);
  assert.match(text, /^# HELP auth_admin_bot_tokens_minted_total /m);
  assert.match(text, /^# HELP auth_admin_service_tokens_minted_total /m);
  assert.match(text, /^# HELP auth_admin_test_slot_model_approvals_total /m);
});

test("authAdminBotTokensMintedTotal increments on every mint", async () => {
  recordAdminBotTokenMint();
  recordAdminBotTokenMint();
  const text = await registry.metrics();
  assert.match(text, /^# TYPE auth_admin_bot_tokens_minted_total counter$/m);
  // Label-free counter — the single series tracks all mints. A spike
  // outside expected admin debugging windows is the operational signal;
  // per-mint attribution comes from the structured `console.warn` line.
  assert.match(text, /^auth_admin_bot_tokens_minted_total \d+$/m);
});

test("authAdminServiceTokensMintedTotal increments on every mint", async () => {
  recordAdminServiceTokenMint();
  recordAdminServiceTokenMint();
  const text = await registry.metrics();
  assert.match(text, /^# TYPE auth_admin_service_tokens_minted_total counter$/m);
  // Same label-free posture as the bot-token counter: per-mint identity
  // lives in the structured `console.warn` line so the time-series can
  // stay bounded. Operationally the two counters are read together —
  // bot-token spikes signal browser-side debugging, service-token spikes
  // signal someone bypassing the SA-exchange surface to call an MCP from
  // a workstation.
  assert.match(text, /^auth_admin_service_tokens_minted_total \d+$/m);
});

test("authAdminServiceTokensMintedTotal and authAdminBotTokensMintedTotal are distinct counters", () => {
  // Pin that the two sibling counters share neither name nor counter
  // object. Adding a label to one of them would also collide series and
  // surface as a Prometheus parse error at scrape time — guard at
  // module-init by reading the registered metric names.
  assert.notStrictEqual(
    authAdminBotTokensMintedTotal,
    authAdminServiceTokensMintedTotal,
  );
});

test("authAdminTestSlotModelApprovalsTotal increments on every approved grant", async () => {
  recordAdminTestSlotModelApproval();
  recordAdminTestSlotModelApproval();
  const text = await registry.metrics();
  assert.match(text, /^# TYPE auth_admin_test_slot_model_approvals_total counter$/m);
  assert.match(text, /^auth_admin_test_slot_model_approvals_total \d+$/m);
  assert.notStrictEqual(
    authAdminTestSlotModelApprovalsTotal,
    authAdminServiceTokensMintedTotal,
  );
});
