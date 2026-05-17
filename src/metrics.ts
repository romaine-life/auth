// Prometheus instrumentation for the auth service.
//
// Scraped by the kube-prometheus-stack via the PodMonitor in
// k8s/templates/podmonitor.yaml. Cardinality discipline mirrors what
// every other romaine.life service follows: no per-user, per-email, or
// per-pod labels — only bounded outcome strings.
//
// Counters are registered against the default global Registry so the
// /metrics endpoint exports everything (plus the built-in Node process
// + GC metrics from collectDefaultMetrics).
//
// See nelsong6/tank-operator#486 stage 5.
import { collectDefaultMetrics, Counter, Registry } from "prom-client";

export const registry = new Registry();

// Initialize Node/process/GC defaults on the same registry — keeps every
// auth-service metric exported through the single /metrics handler.
collectDefaultMetrics({ register: registry, prefix: "auth_" });

// Service-principal exchange (/api/auth/exchange/k8s). The label set
// mirrors the ExchangeFailureReason union in src/service-exchange-helpers.ts
// plus a `success` label for the happy path. Bounded ~10 values.
export const authRomaineExchangeTotal = new Counter({
  name: "auth_romaine_exchange_total",
  help: "Calls to /api/auth/exchange/k8s, labeled by outcome.",
  labelNames: ["result"] as const,
  registers: [registry],
});

// Closed result label set surfaced by the exchange handler. Any new
// reason added to ExchangeFailureReason in service-exchange-helpers.ts
// must also be added here (and to the dashboard panels that consume
// the counter).
export type ExchangeResultLabel =
  | "success"
  | "denied_token"
  | "denied_allowlist"
  | "denied_unbound_pod"
  | "denied_unknown_namespace"
  | "denied_annotation_missing"
  | "denied_pod_lookup_failed"
  | "error_jwt_mint"
  | "error_internal";

export function recordExchange(result: ExchangeResultLabel): void {
  authRomaineExchangeTotal.labels(result).inc();
}

// Glimmung-managed slot origin admin surface (/api/admin/origins/*).
// `result` is one of: success | unauthorized | bad_request | error.
// `method` is the HTTP verb — bounded at GET/PUT/DELETE.
export const adminOriginsRequestsTotal = new Counter({
  name: "auth_admin_origins_requests_total",
  help: "Calls to /api/admin/origins/*, labeled by HTTP method and outcome.",
  labelNames: ["method", "result"] as const,
  registers: [registry],
});

export type AdminOriginsResultLabel =
  | "success"
  | "unauthorized"
  | "bad_request"
  | "error";

export function recordAdminOrigins(method: string, result: AdminOriginsResultLabel): void {
  adminOriginsRequestsTotal.labels(method, result).inc();
}

// Admin bot-token mint (/admin/bot-tokens). Break-glass surface: an
// admin clicks "Mint bot token" on the /admin console to get a 24h
// JWT they can paste into an Authorization: Bearer call (e.g. for
// salvaging a tank-operator session when the UI is broken). Single
// counter (label-free) — this is rare-event telemetry, and a per-mint
// `console.warn` carries the caller email for audit. A spike here
// outside expected admin debugging windows is itself the signal.
export const authAdminBotTokensMintedTotal = new Counter({
  name: "auth_admin_bot_tokens_minted_total",
  help: "Bot tokens minted via /admin/bot-tokens (24h, role=admin, purpose=bot).",
  registers: [registry],
});

export function recordAdminBotTokenMint(): void {
  authAdminBotTokensMintedTotal.inc();
}
