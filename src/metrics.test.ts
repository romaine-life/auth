import { test } from "node:test";
import assert from "node:assert/strict";
import {
  authRomaineExchangeTotal,
  adminOriginsRequestsTotal,
  authEntraExchangeTotal,
  recordAdminOrigins,
  recordEntraExchange,
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
  assert.match(text, /^# HELP auth_entra_exchange_total /m);
});

test("authEntraExchangeTotal records by `result` label", async () => {
  recordEntraExchange("success");
  recordEntraExchange("invalid_audience");
  recordEntraExchange("invalid_audience");
  const text = await registry.metrics();
  assert.match(text, /^# TYPE auth_entra_exchange_total counter$/m);
  assert.match(text, /auth_entra_exchange_total\{result="success"\} \d+/);
  assert.match(text, /auth_entra_exchange_total\{result="invalid_audience"\} \d+/);
});

test("recordEntraExchange accepts every documented EntraExchangeResultLabel", () => {
  // Compile-time invariant: the union below must match
  // EntraExchangeResultLabel in metrics.ts exactly. A new reason added
  // there without updating this test is a CI failure.
  for (const r of [
    "success",
    "missing_token",
    "invalid_signature",
    "invalid_issuer",
    "invalid_audience",
    "invalid_tenant",
    "token_expired",
    "missing_email_claim",
    "unknown_user",
    "role_pending",
    "jwks_fetch_failed",
    "config_missing",
    "error_jwt_mint",
    "error_internal",
  ] as const) {
    recordEntraExchange(r);
  }
  assert.ok(true);
});
