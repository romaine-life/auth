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
// See romaine-life/tank-operator#486 stage 5.
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
  | "denied_actor_override_not_allowed"
  | "denied_actor_email_invalid"
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

// Admin service-token mint (/admin/service-tokens). Sibling surface to
// the bot-token mint above, but produces a `role=service` JWT carrying
// `actor_email=<admin's email>` so the token passes the verifier
// contract that consumers like `romaine-life/mcp-github` pin on
// (`role == "service"` + non-empty `actor_email`). Separate counter
// because the operational signal is different: a bot-token spike is
// "human debugging the apps"; a service-token spike is "human reaching
// past the service-exchange surface to call an MCP from a workstation."
// Same label-free, rare-event posture — per-mint identity lives in the
// structured `console.warn` line.
export const authAdminServiceTokensMintedTotal = new Counter({
  name: "auth_admin_service_tokens_minted_total",
  help: "Service tokens minted via /admin/service-tokens (24h, role=service, purpose=bot, actor_email=<admin>).",
  registers: [registry],
});

export function recordAdminServiceTokenMint(): void {
  authAdminServiceTokensMintedTotal.inc();
}

// Admin-approved Tank git break-glass grants. This is intentionally
// label-free like the bot/service token mint counters: per-request
// identity and repo live in the structured audit log line, while the
// metric tracks rare-event volume without unbounded labels.
export const authAdminGitBreakGlassGrantsTotal = new Counter({
  name: "auth_admin_git_break_glass_grants_total",
  help: "Tank git break-glass grants approved from the auth admin console.",
  registers: [registry],
});

export function recordAdminGitBreakGlassGrant(): void {
  authAdminGitBreakGlassGrantsTotal.inc();
}

export const authAdminAzureBreakGlassGrantsTotal = new Counter({
  name: "auth_admin_azure_break_glass_grants_total",
  help: "Tank azure break-glass grants approved from the auth admin console.",
  registers: [registry],
});

export function recordAdminAzureBreakGlassGrant(): void {
  authAdminAzureBreakGlassGrantsTotal.inc();
}

// External-audience federation exchange (/api/auth/exchange/federation).
// Same shape as the service-exchange counter — bounded label set drawn
// from FederationFailureReason in src/federation-exchange.ts plus a
// `success` label. Distinct metric because the operational signal is
// distinct: a federation-exchange spike means an external IdP (today:
// Tailscale) is being asked to verify our identity, which lives on a
// different dashboard panel from the platform-internal service-exchange
// flow.
export const authFederationExchangeTotal = new Counter({
  name: "auth_federation_exchange_total",
  help: "Calls to /api/auth/exchange/federation, labeled by outcome.",
  labelNames: ["result"] as const,
  registers: [registry],
});

export type FederationExchangeResultLabel =
  | "success"
  | "denied_token"
  | "denied_allowlist"
  | "denied_audience_missing"
  | "denied_audience_not_allowed"
  | "denied_ttl"
  | "error_jwt_mint"
  | "error_internal";

export function recordFederationExchange(result: FederationExchangeResultLabel): void {
  authFederationExchangeTotal.labels(result).inc();
}

// SSH user-certificate exchange (/api/auth/exchange/ssh-cert). auth owns
// the SSH CA key (migration that retired glimmung's local signer) and
// signs short-lived OpenSSH user certs here. Distinct metric because the
// operational signal is distinct: a spike means host-login credentials
// are being minted, which sits on its own dashboard panel and has its own
// alert posture (any sustained `error_ca_unconfigured` means issuance is
// down even though sign-in/federation are fine). Per-mint identity
// (subject, key_id, principals) lives in the structured audit log line,
// NOT in a label — same cardinality discipline as the bot-token mint.
export const authSshCertExchangeTotal = new Counter({
  name: "auth_ssh_cert_exchange_total",
  help: "Calls to /api/auth/exchange/ssh-cert, labeled by outcome.",
  labelNames: ["result"] as const,
  registers: [registry],
});

export type SshCertExchangeResultLabel =
  | "success"
  | "denied_token"
  | "denied_allowlist"
  | "denied_public_key"
  | "denied_key_id"
  | "denied_principal"
  | "denied_extension"
  | "denied_ttl"
  | "error_ca_unconfigured"
  | "error_sign"
  | "error_internal";

export function recordSshCertExchange(result: SshCertExchangeResultLabel): void {
  authSshCertExchangeTotal.labels(result).inc();
}
