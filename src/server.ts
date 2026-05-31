import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { html, raw } from "hono/html";
import { logger } from "hono/logger";
import { setCookie, deleteCookie, getCookie } from "hono/cookie";
import { and, eq, desc } from "drizzle-orm";
import { auth, resolveAllTrustedOrigins } from "./auth.js";
import { db } from "./db/client.js";
import { account, cliDeviceGrant, session, user } from "./db/schema.js";
import {
  appendCallbackParams,
  buildRequesterGuidance,
  CLI_DEVICE_EXPIRES_SECONDS,
  CLI_DEVICE_POLL_INTERVAL_SECONDS,
  decodeRequesterInfo,
  encodeRequesterInfo,
  generateUserCode,
  hashSecret,
  normalizeUserCode,
  previousMiscIdentifiersFromClientNames,
  randomUrlToken,
  requireRequesterInfo,
  validateLoopbackRedirectUri,
  validatePkceInput,
  verifyPkceS256,
  type CliDeviceStatus,
  type CliRequesterInfo,
} from "./cli-device-flow.js";
import {
  deleteProjectOrigins,
  listManagedOrigins,
  listManagedOriginsByProject,
  replaceProjectOrigins,
} from "./managed-origins.js";
import { parseAllowlist, verifyK8sSAToken } from "./k8s-auth.js";
import { matchWildcard } from "./wildcard.js";
import {
  exchangeServiceAccountToken,
  ExchangeError,
} from "./service-exchange.js";
import {
  exchangeFederationToken,
  FederationExchangeError,
} from "./federation-exchange.js";
import {
  exchangeSshCert,
  SshCertExchangeError,
  sshCaPublicKey,
} from "./ssh-cert-exchange.js";
import { mintAuthJwt } from "./mint-jwt.js";
import { isReservedServiceEmail } from "./synthetic-email.js";
import {
  recordAdminBotTokenMint,
  recordAdminOrigins,
  recordAdminServiceTokenMint,
  recordExchange,
  recordFederationExchange,
  recordSshCertExchange,
  registry,
} from "./metrics.js";
import { type JSONWebKeySet } from "jose";
import { verifyAdminBearerJwt } from "./admin-bearer.js";

// Cross-origin fetches from .romaine.life apps that hit /api/auth/* to
// pick up a JWT (silent-exchange path) or check session need CORS
// response headers. Better Auth's `trustedOrigins` only governs CSRF
// and callbackURL validation — it does not set Access-Control-Allow-Origin.
// Hono's cors middleware fills that in, mirroring the trustedOrigins union
// (static prod peers + glimmung-managed slot wildcards). Pattern semantics:
// `*` matches one DNS label, no dots crossed. See src/wildcard.ts.
async function corsOriginMatcher(origin: string): Promise<string | null> {
  if (!origin) return null;
  for (const pattern of await resolveAllTrustedOrigins()) {
    if (matchWildcard(pattern, origin)) return origin;
  }
  return null;
}

const app = new Hono();
app.use("*", logger());

// Apply CORS only to the Better Auth surface — the dashboard at "/" is a
// same-origin HTML page and doesn't need ACA headers, and limiting scope
// keeps preflight cost off the unrelated routes.
app.use(
  "/api/auth/*",
  cors({
    origin: corsOriginMatcher,
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type"],
    maxAge: 600,
  }),
);

app.get("/health", (c) => c.text("ok"));
app.get("/ready", (c) => c.text("ok"));

// Prometheus scrape endpoint. PodMonitor in
// k8s/templates/podmonitor.yaml scrapes /metrics on the auth Service's
// :http port. Exports the auth.romaine.life-side counters (exchange,
// admin-origins) plus default Node/process/GC metrics — see
// src/metrics.ts. Intentionally not CORS-allowlisted (cluster-internal
// only); same posture as /api/admin/origins/*.
app.get("/metrics", async (c) => {
  const body = await registry.metrics();
  return c.text(body, 200, { "Content-Type": registry.contentType });
});

// ── Admin: managed slot origins ────────────────────────────────────────────
// Glimmung's reconciler writes per-project slot wildcards here. The endpoint
// is intentionally NOT CORS-allowlisted — these are machine-to-machine calls
// from inside the cluster, never a browser caller. AuthN is the inbound
// caller's projected k8s SA token (RS256, signed by the AKS OIDC issuer),
// validated against the (namespace, serviceAccount) allowlist.
//
// See nelsong6/glimmung#142 for the cross-repo contract.
//
// In TEST_MODE we skip registration entirely — test slots have no DB and
// no inbound writers; a 404 is the correct surface there.
if (process.env.TEST_MODE !== "true") {
  // Admin path uses the K8S_ADMIN_* env vars; service path (below) uses
  // K8S_SERVICE_*. Both go through the same verifyK8sSAToken but with
  // different pinned audiences and allowlists.
  const ADMIN_AUDIENCE = (
    process.env.K8S_ADMIN_AUDIENCE ?? "https://auth.romaine.life"
  ).trim();
  const ADMIN_ALLOWLIST = parseAllowlist(process.env.K8S_ADMIN_SA_ALLOWLIST ?? "");

  app.use("/api/admin/origins/*", async (c, next) => {
    const method = c.req.method;
    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      recordAdminOrigins(method, "unauthorized");
      return c.json({ error: "missing bearer token" }, 401);
    }
    const token = header.slice("Bearer ".length).trim();
    try {
      // We don't currently surface the verified subject downstream — the
      // allowlist gate is the only authorization check today, and `glimmung`
      // is the only allowed caller. Persisting the subject on c.var would
      // require Hono Variables typing; skip until we have a real second
      // caller.
      await verifyK8sSAToken(token, {
        audience: ADMIN_AUDIENCE,
        allowlist: ADMIN_ALLOWLIST,
      });
    } catch (e) {
      recordAdminOrigins(method, "unauthorized");
      return c.json({ error: `unauthorized: ${(e as Error).message}` }, 401);
    }
    await next();
    // Map the handler's final status into the bounded result label set.
    // 4xx is split into "bad_request" so dashboards can tell a malformed
    // body apart from an upstream/infra failure (5xx → error). 2xx →
    // success. 3xx → success (none of these endpoints redirect today).
    const status = c.res.status;
    let result: "success" | "bad_request" | "error";
    if (status >= 200 && status < 400) result = "success";
    else if (status >= 400 && status < 500) result = "bad_request";
    else result = "error";
    recordAdminOrigins(method, result);
  });

  app.get("/api/admin/origins", async (c) => {
    const rows = await listManagedOrigins();
    return c.json({ origins: rows });
  });

  app.get("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    const wildcards = await listManagedOriginsByProject(project);
    return c.json({ project, wildcards });
  });

  app.put("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    let body: { wildcards?: unknown };
    try {
      body = (await c.req.json()) as { wildcards?: unknown };
    } catch {
      return c.json({ error: "invalid JSON body" }, 400);
    }
    if (
      !Array.isArray(body.wildcards) ||
      !body.wildcards.every((w) => typeof w === "string")
    ) {
      return c.json({ error: "body.wildcards must be a string array" }, 400);
    }
    try {
      await replaceProjectOrigins(project, body.wildcards as string[]);
    } catch (e) {
      return c.json({ error: (e as Error).message }, 422);
    }
    return c.json({
      project,
      wildcards: await listManagedOriginsByProject(project),
    });
  });

  app.delete("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    await deleteProjectOrigins(project);
    return c.json({ project, wildcards: [] });
  });

  // ── Service-principal exchange ───────────────────────────────────────────
  // Tank-operator session pods POST their projected SA token here to
  // receive an auth.romaine.life service-principal JWT (role=service)
  // that downstream apps verify the same way they verify human tokens
  // (same JWKS, same iss/aud, just a new role).
  //
  // Inbound auth is the SA token itself in the Authorization header —
  // no separate caller credential. AuthN gate uses K8S_SERVICE_AUDIENCE
  // and K8S_SERVICE_SA_ALLOWLIST (parallel to the K8S_ADMIN_* env vars
  // above) so a glimmung admin token cannot be replayed as a service
  // principal and vice versa.
  //
  // Registered before Better Auth's /api/auth/* catch-all so this more
  // specific route wins. Body is empty — the token is the entirety of
  // the input. Response shape mirrors the JWT plugin's getToken.
  //
  // See nelsong6/tank-operator#486.
  app.post("/api/auth/exchange/k8s", async (c) => {
    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      recordExchange("denied_token");
      return c.json({ error: "missing bearer token" }, 401);
    }
    const saToken = header.slice("Bearer ".length).trim();
    // Optional JSON body with `actor_email` for the on-behalf-of
    // mint path used by elevated consumers (today: tank-operator
    // orchestrator's mcp-github proxy). Empty/missing/invalid-JSON
    // body falls through to the default flow that derives
    // actor_email from pod annotations. Non-elevated consumers that
    // populate this field still hit the actor-override gate in the
    // exchange and are rejected with denied_actor_override_not_allowed.
    let requestedActorEmail = "";
    if (c.req.header("Content-Length")) {
      try {
        const body = (await c.req.json()) as { actor_email?: unknown };
        if (typeof body?.actor_email === "string") {
          requestedActorEmail = body.actor_email;
        }
      } catch {
        // Treat malformed body as "no actor_email supplied" rather
        // than 400: tank-operator's bootstrap path sends an empty
        // body for the standard exchange and an object body only for
        // the on-behalf-of path. A parse error means "no override."
      }
    }
    try {
      const result = await exchangeServiceAccountToken(saToken, {
        requestedActorEmail,
      });
      recordExchange("success");
      return c.json({
        token: result.token,
        expires_at: result.expiresAt,
        sub: result.userId,
        email: result.email,
        actor_email: result.actorEmail,
        session_id: result.sessionId,
      });
    } catch (e) {
      if (e instanceof ExchangeError) {
        // Reason string is the same closed set the Prometheus counter
        // uses as its label — drives both the response body and the
        // dashboard.
        recordExchange(e.reason);
        return c.json(
          { error: e.message, reason: e.reason },
          e.status as Parameters<typeof c.json>[1],
        );
      }
      console.error("[/api/auth/exchange/k8s] unexpected:", e);
      recordExchange("error_internal");
      return c.json({ error: "internal error", reason: "error_internal" }, 500);
    }
  });

  // ── External-audience federation exchange ───────────────────────────────
  // Workload-identity federation in the RFC 7523 sense: a romaine.life
  // workload presents its projected k8s SA token, asks for a JWT scoped to
  // a specific external audience (today: Tailscale's tailnet identifier),
  // and the third-party IdP verifies the signature against /api/auth/jwks
  // via the root /.well-known/openid-configuration discovery doc.
  //
  // Structurally separate from /api/auth/exchange/k8s: different inbound
  // allowlist, different output shape (no role / actor_email / synthetic
  // user upsert), different audience contract. See
  // src/federation-exchange.ts header for the trust-boundary rationale.
  //
  // Body: { audience: string, ttl_seconds?: number }. Audience matched
  // against FEDERATION_AUDIENCE_ALLOWLIST (env-derived, comma-separated,
  // trailing-`*` suffix patterns supported). Inbound allowlist is
  // K8S_FEDERATION_SA_ALLOWLIST (NOT shared with the service-exchange
  // allowlist — different security context).
  app.post("/api/auth/exchange/federation", async (c) => {
    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      recordFederationExchange("denied_token");
      return c.json({ error: "missing bearer token" }, 401);
    }
    const saToken = header.slice("Bearer ".length).trim();

    let body: { audience?: unknown; ttl_seconds?: unknown };
    try {
      body = (await c.req.json()) as { audience?: unknown; ttl_seconds?: unknown };
    } catch {
      recordFederationExchange("denied_audience_missing");
      return c.json(
        { error: "request body must be JSON with an `audience` field", reason: "denied_audience_missing" },
        400,
      );
    }
    const audience = typeof body.audience === "string" ? body.audience : "";
    const ttlSeconds =
      typeof body.ttl_seconds === "number" ? body.ttl_seconds : undefined;

    try {
      const result = await exchangeFederationToken({
        saToken,
        audience,
        ttlSeconds,
      });
      recordFederationExchange("success");
      return c.json({
        token: result.token,
        expires_at: result.expiresAt,
        sub: result.subject,
        aud: result.audience,
      });
    } catch (e) {
      if (e instanceof FederationExchangeError) {
        recordFederationExchange(e.reason);
        return c.json(
          { error: e.message, reason: e.reason },
          e.status as Parameters<typeof c.json>[1],
        );
      }
      console.error("[/api/auth/exchange/federation] unexpected:", e);
      recordFederationExchange("error_internal");
      return c.json({ error: "internal error", reason: "error_internal" }, 500);
    }
  });

  // ── SSH user-certificate exchange ────────────────────────────────────────
  // auth owns the SSH CA key and signs short-lived OpenSSH user certs here.
  // Inbound: a per-run issuance gateway (today: glimmung's native-runner
  // ssh-cert callback) presents its projected k8s SA token plus a freshly
  // minted ed25519 public key and the run-scoped cert parameters; auth
  // validates/clamps every security-relevant field and signs.
  //
  // Structurally separate from /api/auth/exchange/federation: different
  // signing KEY CLASS (SSH CA ed25519, not the JWKS key), different inbound
  // allowlist (K8S_SSH_CERT_SA_ALLOWLIST), different output (a host login
  // credential, not a bearer JWT). See src/ssh-cert-exchange.ts header.
  //
  // Body: { public_key, key_id, principals[], extensions?[], ttl_seconds? }.
  app.post("/api/auth/exchange/ssh-cert", async (c) => {
    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      recordSshCertExchange("denied_token");
      return c.json({ error: "missing bearer token", reason: "denied_token" }, 401);
    }
    const saToken = header.slice("Bearer ".length).trim();

    let body: {
      public_key?: unknown;
      key_id?: unknown;
      principals?: unknown;
      extensions?: unknown;
      ttl_seconds?: unknown;
    };
    try {
      body = (await c.req.json()) as typeof body;
    } catch {
      recordSshCertExchange("denied_public_key");
      return c.json(
        { error: "request body must be JSON", reason: "denied_public_key" },
        400,
      );
    }

    try {
      const result = await exchangeSshCert({
        saToken,
        publicKey: body.public_key,
        keyId: body.key_id,
        principals: body.principals,
        extensions: body.extensions,
        ttlSeconds: body.ttl_seconds,
      });
      recordSshCertExchange("success");
      // Structured audit line. Per-mint identity lives here, NOT in a
      // metric label (cardinality discipline). The cert body itself is a
      // bearer credential and is never logged.
      console.warn(
        "[ssh-cert] issued",
        JSON.stringify({
          sub: result.subject,
          key_id: result.keyId,
          principals: result.principals,
          valid_before: result.validBefore,
        }),
      );
      return c.json({
        certificate: result.certificate,
        valid_before: result.validBefore,
        sub: result.subject,
        key_id: result.keyId,
        principals: result.principals,
      });
    } catch (e) {
      if (e instanceof SshCertExchangeError) {
        recordSshCertExchange(e.reason);
        return c.json(
          { error: e.message, reason: e.reason },
          e.status as Parameters<typeof c.json>[1],
        );
      }
      console.error("[/api/auth/exchange/ssh-cert] unexpected:", e);
      recordSshCertExchange("error_internal");
      return c.json({ error: "internal error", reason: "error_internal" }, 500);
    }
  });

  // ── SSH CA public key (unauthenticated) ──────────────────────────────────
  // A CA public key is published-by-design: a host populates its
  // TrustedUserCAKeys from it. Served as text/plain so host provisioning
  // can `curl https://auth.romaine.life/api/ssh/ca >> trusted-ca.pub`.
  // 404 when the CA is unconfigured (env SSH_CA_PRIVATE_KEY unset) so a
  // misconfigured deploy is loud rather than serving an empty trust anchor.
  app.get("/api/ssh/ca", (c) => {
    const pub = sshCaPublicKey();
    if (!pub) {
      return c.text("SSH CA not configured", 404);
    }
    return c.text(pub + "\n", 200, { "content-type": "text/plain; charset=utf-8" });
  });

  // ── User-token CLI flow routes ───────────────────────────────────────────
  // Registered HERE (inside the TEST_MODE-false block) so they land before
  // the `app.on(["GET", "POST"], "/api/auth/*", auth.handler)` catch-all
  // a few dozen lines below. Hono is first-match-wins; a /api/auth/cli/*
  // path registered after the catch-all would be silently shadowed and
  // return 404. The grant store + helpers above live at module scope;
  // only the registrations need to be in this block.
  //
  // See the block-level docs near `userLoginGrants` for the flow.

  app.get("/api/auth/cli/user-login", async (c) => {
    let redirectUri: string;
    let codeChallenge: string;
    let state: string | null;
    try {
      const validated = validateLoopbackRedirectUri(c.req.query("redirect_uri"));
      if (!validated) throw new Error("redirect_uri is required");
      redirectUri = validated;
      const pkce = validatePkceInput(
        redirectUri,
        c.req.query("code_challenge"),
        c.req.query("code_challenge_method"),
      );
      if (!pkce.codeChallenge) throw new Error("code_challenge is required");
      codeChallenge = pkce.codeChallenge;
      state = (c.req.query("state") ?? "").slice(0, 500) || null;
    } catch (e) {
      return c.text((e as Error).message, 400);
    }

    // If not signed in, bounce through Microsoft sign-in and come back here
    // with the same params so the signed-in branch fires on the next pass.
    // Google works too — Microsoft is the default to match the dashboard.
    const sessionResult = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!sessionResult) {
      const self = new URL("/api/auth/cli/user-login", publicBaseUrl(c));
      self.searchParams.set("redirect_uri", redirectUri);
      self.searchParams.set("code_challenge", codeChallenge);
      self.searchParams.set("code_challenge_method", "S256");
      if (state) self.searchParams.set("state", state);
      return c.redirect(`/sign-in/microsoft?callbackURL=${encodeURIComponent(self.toString())}`);
    }

    // Refuse role=pending — downstream apps reject pending users anyway, so
    // a token issued here would just fail at the next API call.
    const u = sessionResult.user as typeof sessionResult.user & { role?: string };
    if (u.role !== "admin" && u.role !== "user") {
      return c.text(
        "Your romaine.life account is pending admin approval. Try again after an admin promotes you.",
        403,
      );
    }

    pruneExpiredUserLoginGrants();
    const code = randomUrlToken();
    userLoginGrants.set(hashSecret(code), {
      userId: u.id,
      redirectUri,
      codeChallenge,
      state,
      expiresAt: Date.now() + USER_LOGIN_CODE_TTL_SECONDS * 1000,
    });

    return c.redirect(appendCallbackParams(redirectUri, code, state));
  });

  app.post("/api/auth/cli/user-token", async (c) => {
    let body: Record<string, unknown>;
    try {
      body = await readJsonObject(c);
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }

    if (body.grant_type !== "authorization_code") {
      return oauthError(c, "unsupported_grant_type");
    }
    if (typeof body.code !== "string" || !body.code) {
      return oauthError(c, "invalid_request", 400, { error_description: "code is required" });
    }
    if (typeof body.code_verifier !== "string" || !body.code_verifier) {
      return oauthError(c, "invalid_request", 400, { error_description: "code_verifier is required" });
    }
    if (typeof body.redirect_uri !== "string" || !body.redirect_uri) {
      return oauthError(c, "invalid_request", 400, { error_description: "redirect_uri is required" });
    }

    pruneExpiredUserLoginGrants();
    const codeHash = hashSecret(body.code);
    const grant = userLoginGrants.get(codeHash);
    if (!grant) return oauthError(c, "invalid_grant");
    // Single-use: drop the grant immediately so a leaked code can't be replayed.
    userLoginGrants.delete(codeHash);

    if (grant.expiresAt <= Date.now()) return oauthError(c, "expired_token");
    if (grant.redirectUri !== body.redirect_uri) {
      return oauthError(c, "invalid_grant", 400, { error_description: "redirect_uri mismatch" });
    }
    if (!verifyPkceS256(body.code_verifier, grant.codeChallenge)) {
      return oauthError(c, "invalid_grant", 400, { error_description: "PKCE verification failed" });
    }

    // Re-read the user row at mint time — a role change between code
    // issuance and exchange (admin demoting someone mid-flow) should be
    // reflected in what we issue.
    const rows = await db.select().from(user).where(eq(user.id, grant.userId)).limit(1);
    const u = rows[0];
    if (!u) return oauthError(c, "invalid_grant", 400, { error_description: "user no longer exists" });
    if (u.role !== "admin" && u.role !== "user") {
      return oauthError(c, "access_denied", 403, { error_description: "account is not approved" });
    }

    let apps: Record<string, unknown> = {};
    try { apps = JSON.parse(u.apps ?? "{}"); } catch {}

    try {
      const signed = await mintAuthJwt({
        sub: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        apps,
        ttlSeconds: USER_LOGIN_TOKEN_TTL_SECONDS,
      });
      console.warn(
        "[/api/auth/cli/user-token] minted:",
        JSON.stringify({ email: u.email, role: u.role, exp: signed.exp }),
      );
      return c.json({
        token: signed.token,
        expires_at: signed.exp,
        expires_in_hours: USER_LOGIN_TOKEN_TTL_SECONDS / 3600,
      });
    } catch (e) {
      console.error("[/api/auth/cli/user-token] mint failed:", e);
      return c.json({ error: "failed to mint token" }, 500);
    }
  });

}

// TEST_MODE flips every handler into fixture-data mode. Used by helm-issue
// per-slot deployments at *.auth.dev.romaine.life so operators can cruise
// the UI without standing up a dev DB or dev OAuth backend. The auth and
// db modules still init (with placeholder env), but their methods are
// never reached in test mode.
const TEST_MODE = process.env.TEST_MODE === "true";
const TEST_COOKIE = "auth-test-signed-in";
const TEST_COOKIE_DOMAIN = process.env.COOKIE_DOMAIN ?? undefined;

function setTestCookie(c: Context) {
  setCookie(c, TEST_COOKIE, "1", {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    maxAge: 86400,
    domain: TEST_COOKIE_DOMAIN,
  });
}
function clearTestCookie(c: Context) {
  deleteCookie(c, TEST_COOKIE, { path: "/", domain: TEST_COOKIE_DOMAIN });
}
function isTestSignedIn(c: Context): boolean {
  return getCookie(c, TEST_COOKIE) === "1";
}

if (TEST_MODE) {
  // Mock JWKS so the topbar JS that fetches `/api/auth/jwks` sees a kid and
  // renders it. Real Better Auth never gets invoked.
  app.get("/api/auth/jwks", (c) =>
    c.json({
      keys: [
        {
          kty: "RSA",
          use: "sig",
          alg: "RS256",
          kid: "test1234",
          n: "test-mode-public-key-modulus-placeholder",
          e: "AQAB",
        },
      ],
    }),
  );
} else {
  // Mount Better Auth at /api/auth/*. Handles sign-in flows, JWKS, sessions, etc.
  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));
}

// ── OIDC discovery at the ROOT ─────────────────────────────────────────────
// Better Auth's OIDC provider plugin (src/auth.ts) already serves a
// discovery doc at /api/auth/.well-known/openid-configuration. That URL
// is fine for relying parties we configure by hand (Grafana doesn't
// autodiscover). External IdPs that treat us as a workload-identity
// federation issuer — today: Tailscale's "Trust credentials" OIDC type —
// fetch the discovery doc at the ROOT of the issuer URL, with no
// `/api/auth` prefix. RFC 8414 pins the discovery path as
// `<issuer>/.well-known/openid-configuration`.
//
// We hand-build this doc rather than proxying Better Auth's full one. It
// serves two distinct classes of consumer, both of which fetch discovery
// at the ROOT of the issuer:
//   1. Workload-identity-federation verifiers (Tailscale's "Trust
//      credentials" OIDC type). They only read `issuer` + `jwks_uri` to
//      verify a JWT we already minted — they ignore every other field.
//   2. OIDC relying parties that AUTODISCOVER and enforce issuer-match
//      (Argo CD's native OIDC client). Argo CD fetches `<issuer>/.well-known/
//      openid-configuration`, requires the doc's `issuer` to equal the
//      configured issuer, and derives the authorize/token endpoints from it
//      rather than letting you set them by hand. So it can only consume a
//      root-served doc whose `issuer` is the bare origin AND which advertises
//      the oauth2 endpoints. (Grafana, by contrast, configures those
//      endpoints explicitly and never touches this doc.)
//
// The authorize/token/userinfo endpoints below point at the Better-Auth
// `oidcProvider` routes under /api/auth/oauth2/*. The non-root prefix is
// fine: RPs follow these URLs verbatim from the discovery doc. Class-1
// (Tailscale) consumers ignore them. Both this doc and the Better-Auth doc
// advertise the same `issuer` and `jwks_uri`, so any tool that follows
// discovery to the JWKS lands on the same public key set either way.
app.get("/.well-known/openid-configuration", (c) => {
  const issuer = (process.env.BASE_URL ?? "https://auth.romaine.life").replace(/\/$/, "");
  return c.json({
    issuer,
    jwks_uri: `${issuer}/api/auth/jwks`,
    // The oauth2 code-flow endpoints, served by the Better-Auth
    // `oidcProvider` plugin (src/auth.ts) under /api/auth/oauth2/*.
    // Autodiscovering RPs (Argo CD's native OIDC client) need these here at
    // the root because the issuer-match check forbids pointing them at the
    // /api/auth-prefixed discovery doc (whose `issuer` is still the root).
    authorization_endpoint: `${issuer}/api/auth/oauth2/authorize`,
    token_endpoint: `${issuer}/api/auth/oauth2/token`,
    userinfo_endpoint: `${issuer}/api/auth/oauth2/userinfo`,
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    response_types_supported: ["code", "id_token"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    scopes_supported: ["openid", "profile", "email"],
  });
});

// ── Landing / dashboard ────────────────────────────────────────────────────
// Server-rendered HTML. Anonymous: welcome + sign-in buttons. Authenticated:
// user info, linked accounts, recent sessions, granted apps, raw claims.
// Visual treatment: Voight-Kampff (Blade Runner / PKD) — amber CRT on inky
// brown, iris animation, off-world emigration ticker, pyramid corner mark.
// Design handoff from claude.ai/design lives in design-fetch/.

const BUILD = (process.env.GIT_SHA ?? "dev").slice(0, 7);

// Generate the iris SVG once at module load. Procedural geometry — 24
// filaments + 60 minor ticks (skipping every 5th) — same shape the design's
// React component renders, but rendered server-side as static markup.
function buildIris(): string {
  const filaments: string[] = [];
  for (let i = 0; i < 24; i++) {
    const a = (i / 24) * Math.PI * 2;
    const x1 = (84 + Math.cos(a) * 22).toFixed(2);
    const y1 = (84 + Math.sin(a) * 22).toFixed(2);
    const x2 = (84 + Math.cos(a) * 36).toFixed(2);
    const y2 = (84 + Math.sin(a) * 36).toFixed(2);
    filaments.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.55"/>`);
  }
  const ticks: string[] = [];
  for (let i = 0; i < 60; i++) {
    if (i % 5 === 0) continue;
    const a = (i / 60) * Math.PI * 2;
    const r1 = 78, r2 = 80;
    const x1 = (84 + Math.cos(a) * r1).toFixed(2);
    const y1 = (84 + Math.sin(a) * r1).toFixed(2);
    const x2 = (84 + Math.cos(a) * r2).toFixed(2);
    const y2 = (84 + Math.sin(a) * r2).toFixed(2);
    ticks.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.3"/>`);
  }
  return `<svg class="iris" width="168" height="168" viewBox="0 0 168 168" fill="none" aria-hidden="true">
    <circle cx="84" cy="84" r="80" stroke="currentColor" stroke-width="0.7" opacity="0.25"/>
    <circle cx="84" cy="84" r="66" stroke="currentColor" stroke-width="0.7" opacity="0.4"/>
    <circle cx="84" cy="84" r="50" stroke="currentColor" stroke-width="1"/>
    <circle cx="84" cy="84" r="36" stroke="currentColor" stroke-width="0.7" opacity="0.7"/>
    <circle cx="84" cy="84" r="22" stroke="currentColor" stroke-width="0.5" opacity="0.85"/>
    <circle cx="84" cy="84" r="9" fill="currentColor"/>
    ${filaments.join("")}
    <line x1="84" y1="2" x2="84" y2="16" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="84" y1="152" x2="84" y2="166" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="2" y1="84" x2="16" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="152" y1="84" x2="166" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    ${ticks.join("")}
  </svg>`;
}
const IRIS = raw(buildIris());

const IRIS_MINI = raw(`<svg class="iris-mini" width="56" height="56" viewBox="0 0 64 64" fill="none" aria-hidden="true">
  <circle cx="32" cy="32" r="28" stroke="currentColor" stroke-width="0.6" opacity="0.4"/>
  <circle cx="32" cy="32" r="20" stroke="currentColor" stroke-width="0.8"/>
  <circle cx="32" cy="32" r="12" stroke="currentColor" stroke-width="0.5" opacity="0.7"/>
  <circle cx="32" cy="32" r="4" fill="currentColor"/>
  <line x1="32" y1="0" x2="32" y2="6" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="32" y1="58" x2="32" y2="64" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="0" y1="32" x2="6" y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="58" y1="32" x2="64" y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
</svg>`);

const BRAND_MARK = raw(`<svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <circle cx="16" cy="16" r="14" stroke="currentColor" stroke-width="1" opacity="0.5"/>
  <circle cx="16" cy="16" r="9" stroke="currentColor" stroke-width="1"/>
  <circle cx="16" cy="16" r="3" fill="currentColor"/>
</svg>`);

// Microsoft sign-in button per the official brand guidelines:
// https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-branding-in-apps
const MSFT_LOGO = raw(`<svg class="signin-logo" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#F35325"/><rect x="11" y="1" width="9" height="9" fill="#81BC06"/><rect x="1" y="11" width="9" height="9" fill="#05A6F0"/><rect x="11" y="11" width="9" height="9" fill="#FFBA08"/></svg>`);

const GOOGLE_LOGO = raw(`<svg class="signin-logo" viewBox="0 0 24 24" aria-hidden="true">
  <path fill="#EA4335" d="M12 10.2v3.9h5.5c-.24 1.5-1.7 4.3-5.5 4.3-3.3 0-6-2.7-6-6.1S8.7 6.2 12 6.2c1.9 0 3.1.8 3.9 1.5l2.6-2.5C16.9 3.7 14.6 2.7 12 2.7 6.9 2.7 2.8 6.8 2.8 12s4.1 9.3 9.2 9.3c5.3 0 8.8-3.7 8.8-9 0-.6-.1-1.1-.2-1.6H12z"/>
  <path fill="#4285F4" d="M21 12.3c0-.6-.1-1.1-.2-1.6H12v3.9h5.5c-.2 1.3-1 2.4-2.1 3.1l3.3 2.5C20.8 18.7 21 15.7 21 12.3z"/>
  <path fill="#FBBC05" d="M5.8 14.1c-.2-.6-.3-1.2-.3-1.9s.1-1.3.3-1.9L2.8 8.1A9.27 9.27 0 0 0 2.8 16l3-1.9z"/>
</svg>`);

const CLOCK_ICON = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5"/>
  <path d="M12 7v5l3 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>`);

const KEY_ICON = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="7" cy="12" r="3.5" stroke="currentColor" stroke-width="1.6"/>
  <path d="M10.5 12h10M17.5 12v3M21 12v2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
</svg>`);

const PYRAMID = raw(`<div class="corner-mark" aria-hidden="true">       ▲
      ▲ ▲
     ▲   ▲
    ▲  ◉  ▲
   ▲       ▲
  ▲▲▲▲▲▲▲▲▲
TYRELL · NEXUS-7</div>`);

// Known *.romaine.life apps shown in the Authorized Modules tile grid. The
// `granted` flag on signed-in view comes from the user's `apps` JSON blob:
// any key matching `name` here counts as granted, and the value (if any)
// becomes the prefs count.
const ROMAINE_APPS = [
  { host: "homepage.romaine.life",     name: "homepage" },
  { host: "workout.romaine.life",      name: "kill-me" },
  { host: "investing.romaine.life",    name: "investing" },
  { host: "diagrams.romaine.life",     name: "diagrams" },
  { host: "tank.romaine.life",         name: "tank-operator" },
  { host: "fzt-frontend.romaine.life", name: "fzt-frontend" },
  { host: "glimmung.romaine.life",     name: "glimmung" },
];

// VK-style probe questions, rotated client-side on the signed-out card.
// Original copy — same interrogative rhythm as the film's test ("describe
// in single words"), but written fresh.
const EMPATHY_PROMPTS = [
  "You're walking through a corridor of mirrors. One reflection blinks before you do. You stop. Account for the time elapsed before you continue.",
  "A neighbour's terrier slips on the sidewalk. Its leg breaks audibly. The owner is three apartments away. Describe the next thirty seconds.",
  "Your grandmother sends a recording of her voice on your birthday. She has been dead nine years. You play it twice. Explain the second time.",
  "A child you don't recognise hands you a folded paper boat. You unfold it; the inside is blank. The child has gone. Describe your face in the next moment.",
  "An attendant at the duty-free counter asks if you have anything to declare. You are carrying only a paperback. You hesitate. Why.",
  "You wake at 4:11 a.m. to a perfect copy of your own handwriting on the wall above the bed. The handwriting is dry. Continue.",
];

// Cinematic atmosphere strip in the footer — derivative pitches, not movie
// dialogue. Rotates every 6.4s.
const OFFWORLD_PITCHES = [
  "off-world emigration · sectors 1138–2049 accepting applicants · embark Q3 2089",
  "a new sun. a new soil. carbon-stipend on signing · port terminal 14",
  "twin moons · pre-fab habitats · 8-year colonist warranty",
  "leave the dust behind. golden land. begin again — petition Tyrell relocation",
  "courier vessels weekly · standard manifest · no biometric exit fee",
  "sponsored: SHIMATA-DOMINGUEZ aerospace · clear-air corridors only",
];

// ── Inline stylesheet ─────────────────────────────────────────────────────
// Distilled from the design handoff (design-fetch/auth/project/design/
// styles.css + colors_and_type.css). Only the `vk` theme is shipped to
// production — austere/hybrid variants and the dev tweaks panel are dropped.
const STYLES = raw(`
:root {
  --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
  --font-primary: "Archivo", "Vazirmatn", var(--font-sans);
  --font-mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "Consolas", monospace;

  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-2xl: 1.5rem;
  --text-3xl: 1.875rem;

  --gray-950: #0c0907;
  --gray-900: #140e0a;
  --gray-850: #1c130d;
  --gray-800: #3a2614;
  --gray-700: #5a3a18;
  --gray-500: #9b9b9b;
  --gray-400: #b4b4b4;

  --bg-app:        #0a0807;
  --bg-hover-soft: rgba(255, 255, 255, 0.05);

  --border-subtle: rgba(255, 122, 58, 0.12);
  --border-strong: rgba(255, 122, 58, 0.22);

  --fg-primary:   #ffffff;
  --fg-body:      #e6cab0;
  --fg-secondary: #f4d8b8;
  --fg-muted:     #b08858;
  --fg-faint:     #8c5a26;

  --vk-accent:      #ff7a3a;
  --vk-accent-soft: rgba(255, 122, 58, 0.16);
  --vk-iris-glow:   0 0 32px rgba(255, 107, 53, 0.35);
  --vk-grid:        rgba(255, 122, 58, 0.04);

  --status-online:    #ffb073;
  --status-online-bg: rgba(255, 122, 58, 0.14);
  --status-error:     #ef6f6f;
  --status-error-bg:  rgba(239, 111, 111, 0.12);
  --status-pending:   var(--gray-400);

  --radius-sm:   0.375rem;
  --radius-md:   0.5rem;
  --radius-lg:   0.75rem;
  --radius-pill: 9999px;

  --ease-out: cubic-bezier(0.22, 0.61, 0.36, 1);
}

* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  background: var(--bg-app);
  color: var(--fg-body);
  font-family: var(--font-sans);
  font-size: var(--text-sm);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}

/* faint dot-grid backdrop */
body::after {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image: radial-gradient(var(--vk-grid) 1px, transparent 1px);
  background-size: 24px 24px;
  background-position: center;
  mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
  -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
}
/* CRT scanlines */
body::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(
    to bottom,
    rgba(255, 122, 58, 0.04) 0px,
    rgba(255, 122, 58, 0.04) 1px,
    transparent 1px,
    transparent 3px
  );
  mix-blend-mode: screen;
}

button { cursor: pointer; font: inherit; background: transparent; color: inherit; border: none; padding: 0; outline: none; }
button:disabled { cursor: default; opacity: 0.55; }
a { color: var(--fg-secondary); text-decoration: none; }
code, kbd, samp {
  font-family: var(--font-mono);
  font-size: 0.85em;
  background: var(--gray-850);
  padding: 0.05rem 0.25rem;
  border-radius: var(--radius-sm);
}

/* ── Stage ───────────────────────────────────────────────────────── */

.stage {
  position: relative;
  z-index: 1;
  height: 100%;
  display: grid;
  grid-template-rows: auto 1fr auto;
  padding: 28px clamp(20px, 5vw, 64px);
  max-width: 1080px;
  margin: 0 auto;
}

/* ── Top bar ─────────────────────────────────────────────────────── */

.topbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 24px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand {
  display: flex; align-items: center; gap: 12px;
  font-family: var(--font-primary);
}
.brand-mark {
  width: 32px; height: 32px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--vk-accent);
}
.brand-text { display: flex; flex-direction: column; gap: 2px; line-height: 1; }
.brand-text .lockup { font-size: 14px; font-weight: 500; letter-spacing: -0.005em; color: var(--fg-primary); }
.brand-text .lockup .dim { color: var(--fg-faint); font-weight: 400; }
.brand-text .division { font-size: 10px; font-weight: 500; letter-spacing: 0.18em; text-transform: uppercase; color: var(--fg-faint); }

.topbar-meta {
  display: flex; align-items: center; gap: 16px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
}
.topbar-meta .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--status-online); box-shadow: 0 0 8px var(--status-online); }
.topbar-meta .sep { color: var(--gray-800); }
@media (max-width: 640px) {
  .topbar-meta .meta-hide-sm { display: none; }
}

/* ── Main column ────────────────────────────────────────────────── */

.main {
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 24px 0;
  min-height: 0;
  overflow-y: auto;
}
.main > * { margin-block: auto; }

/* ── Signed-out card ────────────────────────────────────────────── */

.vk-card {
  width: 100%;
  max-width: 520px;
  display: flex; flex-direction: column; align-items: center;
  text-align: center;
  gap: 8px;
  animation: vk-fade-in 360ms var(--ease-out);
}
@keyframes vk-fade-in {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: none; }
}
.vk-card .iris-wrap {
  position: relative;
  width: 168px; height: 168px;
  margin: 8px 0 18px;
  display: flex; align-items: center; justify-content: center;
  filter: drop-shadow(var(--vk-iris-glow));
}
.vk-card .iris {
  color: var(--vk-accent);
  animation: iris-breathe 4.5s ease-in-out infinite;
}
@keyframes iris-breathe {
  0%, 100% { opacity: 0.85; transform: scale(1); }
  50%      { opacity: 1;    transform: scale(1.035); }
}
.vk-card h1 {
  font-family: var(--font-primary);
  font-size: 30px; font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--fg-primary);
  margin: 0;
}
.vk-card .subtitle {
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.25em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin: 4px 0 0;
}
.vk-card .lede {
  font-size: 14px;
  color: var(--fg-muted);
  max-width: 380px;
  margin: 16px auto 4px;
  line-height: 1.55;
  text-wrap: pretty;
}
.vk-card .epigraph {
  font-family: var(--font-mono);
  font-size: 12px;
  font-style: italic;
  color: var(--fg-faint);
  margin: 0 0 28px;
}

.signin-stack { display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 320px; }
.signin-btn {
  display: flex; align-items: center; gap: 12px;
  height: 44px; padding: 0 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: var(--gray-900);
  color: var(--fg-primary);
  font-family: var(--font-primary);
  font-size: 14px; font-weight: 500;
  text-align: left;
  transition: background 120ms var(--ease-out), border-color 120ms var(--ease-out), transform 120ms var(--ease-out);
  text-decoration: none;
  width: 100%;
}
.signin-btn:hover { background: var(--gray-850); border-color: var(--gray-700); }
.signin-btn:active { transform: translateY(1px); }
.signin-btn .signin-label { flex: 1; }
.signin-btn .signin-meta {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  color: var(--fg-faint);
  text-transform: uppercase;
}
.signin-btn .signin-logo { width: 20px; height: 20px; display: inline-flex; }
.signin-form { width: 100%; }

.vk-footnote {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  margin: 24px 0 0;
  letter-spacing: 0.04em;
}

/* ── Empathy prompt (signed-out) ─────────────────────────────────── */

.empathy-prompt {
  width: 100%;
  max-width: 460px;
  margin: 6px auto 26px;
  text-align: left;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-md);
  background: var(--gray-950);
  padding: 12px 14px 14px;
  position: relative;
}
.empathy-prompt::before {
  content: "";
  position: absolute; left: 0; top: 0; bottom: 0;
  width: 2px;
  background: var(--vk-accent);
  opacity: 0.4;
  border-radius: 1px;
}
.empathy-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin-bottom: 6px;
}
.empathy-num { color: var(--vk-accent); }
.empathy-body {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--fg-secondary);
  text-wrap: pretty;
  min-height: 4em;
  animation: empathy-fade 480ms var(--ease-out);
}
@keyframes empathy-fade {
  from { opacity: 0; transform: translateY(3px); }
  to   { opacity: 1; transform: none; }
}

/* ── Signed-in dashboard ─────────────────────────────────────────── */

.dash {
  width: 100%;
  max-width: 880px;
  margin: 0 auto;
  display: flex; flex-direction: column;
  gap: 20px;
  animation: vk-fade-in 360ms var(--ease-out);
}
.dash-head {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 20px;
  padding: 18px 20px;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background: linear-gradient(180deg, rgba(255,255,255,0.018), rgba(255,255,255,0)), var(--gray-950);
}
.dash-head .iris-mini-wrap {
  width: 64px; height: 64px;
  display: flex; align-items: center; justify-content: center;
  color: var(--vk-accent);
  filter: drop-shadow(var(--vk-iris-glow));
}
.dash-head .head-text { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.dash-head .head-name {
  font-family: var(--font-primary);
  font-size: 22px; font-weight: 600;
  letter-spacing: -0.015em;
  color: var(--fg-primary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dash-head .head-email {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg-muted);
}
.dash-head .head-designation {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin-top: 4px;
  flex-wrap: wrap;
}
.dash-head .nexus-tag {
  padding: 1px 6px;
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
  letter-spacing: 0.16em;
}
.dash-head .nexus-id { color: var(--fg-secondary); letter-spacing: 0.16em; }
.dash-head .nexus-sep { color: var(--gray-800); }
.dash-head .head-status {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--status-online);
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 2px;
}
.dash-head .head-status .blink-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--status-online);
  animation: blink 1.6s steps(2) infinite;
}
.dash-head .head-aside { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }

.role-badge {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 6px 10px;
  border-radius: var(--radius-pill);
  font-family: var(--font-primary);
  font-size: 11px; font-weight: 500;
  letter-spacing: 0.04em;
  border: 1px solid var(--gray-800);
  color: var(--fg-secondary);
  background: var(--gray-900);
}
.role-badge.is-admin {
  color: var(--vk-accent);
  border-color: color-mix(in oklab, var(--vk-accent), transparent 70%);
  background: var(--vk-accent-soft);
  text-shadow: 0 0 8px color-mix(in oklab, var(--vk-accent), transparent 50%);
}
.role-badge.is-pending {
  color: var(--status-pending);
  border-color: var(--gray-800);
  background: var(--gray-900);
}
.role-badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

.end-btn, .admin-btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: transparent;
  color: var(--fg-secondary);
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.04em;
  transition: background 120ms var(--ease-out), border-color 120ms var(--ease-out), color 120ms var(--ease-out);
  text-decoration: none;
}
.end-btn:hover {
  color: var(--status-error);
  border-color: color-mix(in oklab, var(--status-error), transparent 60%);
  background: var(--status-error-bg);
}
.admin-btn:hover {
  color: var(--vk-accent);
  border-color: color-mix(in oklab, var(--vk-accent), transparent 60%);
  background: var(--vk-accent-soft);
}

.signout-form { display: inline; margin: 0; }

/* sections */
.dash-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.dash-grid > .col-span-2 { grid-column: span 2; }
@media (max-width: 720px) {
  .dash-grid { grid-template-columns: 1fr; }
  .dash-grid > .col-span-2 { grid-column: auto; }
  .dash-head { grid-template-columns: auto 1fr; }
  .dash-head .head-aside { grid-column: span 2; flex-direction: row; align-items: center; justify-content: space-between; }
}

.section {
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background: var(--gray-950);
  overflow: hidden;
}
.section-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 14px 10px;
  gap: 12px;
  border-bottom: 1px solid var(--gray-800);
  background: rgba(255,255,255,0.012);
}
.section-head .title {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--fg-secondary);
}
.section-head .title .sigil {
  font-family: var(--font-mono);
  color: var(--fg-faint);
  font-size: 11px;
  letter-spacing: 0.04em;
}
.section-head .title .meta {
  font-family: var(--font-mono);
  font-weight: 400;
  letter-spacing: 0;
  text-transform: none;
  color: var(--fg-faint);
  margin-left: 6px;
}
.section-head .count {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--fg-faint);
}
.section-body { padding: 6px; }
.section-body .empty {
  padding: 18px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  font-style: italic;
  color: var(--fg-faint);
  text-align: center;
}

/* rows */
.row {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  transition: background 120ms var(--ease-out);
}
.row:hover { background: var(--bg-hover-soft); }
.row .row-icon {
  width: 22px; height: 22px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--fg-secondary);
}
.row .row-main { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.row .row-primary {
  font-family: var(--font-primary);
  font-size: 13px;
  color: var(--fg-primary);
  font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .row-secondary {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  overflow: hidden; text-overflow: ellipsis;
}
.row .pill {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  background: var(--gray-850);
  color: var(--fg-secondary);
  letter-spacing: 0.04em;
}
.row .pill.current {
  background: color-mix(in oklab, var(--status-online), transparent 80%);
  color: var(--status-online);
}

/* apps grid */
.apps {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 6px;
  padding: 8px;
}
.app-tile {
  display: flex; flex-direction: column; gap: 4px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-850);
  background: rgba(255,255,255,0.015);
  text-align: left;
  text-decoration: none;
  color: inherit;
  transition: background 120ms, border-color 120ms, transform 120ms;
}
.app-tile:hover { background: var(--bg-hover-soft); border-color: var(--gray-800); }
.app-tile.granted { border-color: color-mix(in oklab, var(--vk-accent), transparent 75%); }
.app-tile.granted:hover { border-color: color-mix(in oklab, var(--vk-accent), transparent 55%); }
.app-tile .app-name {
  font-family: var(--font-primary);
  font-size: 13px;
  color: var(--fg-primary);
  font-weight: 500;
}
.app-tile .app-host {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-muted);
}
.app-tile .app-host strong { color: var(--fg-primary); font-weight: 500; }
.app-tile .app-foot {
  display: flex; align-items: center; justify-content: space-between;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--fg-faint);
}
.app-tile.granted .app-foot .ok { color: var(--vk-accent); }

/* claims viewer */
.claims-wrap { padding: 8px; }
.claims {
  margin: 0;
  padding: 14px 16px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.65;
  color: var(--fg-body);
  background: #000;
  border-radius: var(--radius-md);
  overflow-x: auto;
  white-space: pre;
}
.claims .k { color: var(--vk-accent); }
.claims .s { color: var(--status-online); }
.claims .n { color: #c8b6f5; }
.claims .b { color: #e6b59a; }
.claims .p { color: var(--fg-faint); }

.claims-tabs { display: inline-flex; gap: 4px; }
.claims-tab, .claims-copy {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  color: var(--fg-faint);
  transition: color 120ms, background 120ms;
}
.claims-tab.is-active { color: var(--fg-primary); background: var(--gray-850); }
.claims-tab:hover:not(.is-active),
.claims-copy:hover { color: var(--fg-primary); background: var(--gray-850); }
.claims-copy.is-copied { color: var(--status-online); }

/* pending callout */
.pending-callout {
  border: 1px solid var(--gray-800);
  border-left: 2px solid var(--vk-accent);
  border-radius: var(--radius-md);
  background: var(--gray-950);
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg-muted);
  line-height: 1.55;
}

/* ── Footer ─────────────────────────────────────────────────────── */

.footer {
  display: flex; flex-direction: column;
  gap: 0;
  padding-top: 14px;
  border-top: 1px solid var(--border-subtle);
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  letter-spacing: 0.04em;
}
.footer-row { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; }
.footer-links { display: inline-flex; gap: 14px; flex-wrap: wrap; }
.footer-links a {
  color: var(--fg-faint);
  border-bottom: 1px dotted transparent;
  transition: color 120ms, border-color 120ms;
}
.footer-links a:hover {
  color: var(--vk-accent);
  border-bottom-color: color-mix(in oklab, var(--vk-accent), transparent 60%);
}
.footer-sigil { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.3em; }

.offworld-ticker {
  display: flex; align-items: center; gap: 12px;
  margin-top: 10px;
  padding: 6px 10px;
  border: 1px dashed var(--border-subtle);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.04em;
  color: var(--fg-muted);
  background: linear-gradient(90deg, color-mix(in oklab, var(--vk-accent), transparent 92%), transparent 60%);
  overflow: hidden;
}
.offworld-tag {
  flex-shrink: 0;
  font-size: 9px; font-weight: 600;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  padding: 2px 6px;
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
}
.offworld-line {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  animation: offworld-fade 6.4s ease-in-out infinite;
}
@keyframes offworld-fade {
  0%, 5%   { opacity: 0; transform: translateX(8px); }
  10%, 85% { opacity: 1; transform: none; }
  95%,100% { opacity: 0; transform: translateX(-8px); }
}

/* ── Corner mark ────────────────────────────────────────────────── */

.corner-mark {
  position: fixed;
  right: 18px; bottom: 16px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--fg-faint);
  letter-spacing: 0.2em;
  line-height: 1.15;
  text-align: right;
  pointer-events: none;
  z-index: 2;
  opacity: 0.55;
  white-space: pre;
}
@media (max-width: 720px) { .corner-mark { display: none; } }

@keyframes blink { 50% { opacity: 0; } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 1ms !important;
    transition-duration: 1ms !important;
  }
}

/* ── Admin console (carried over, restyled to match) ────────────── */

.admin-list { display: flex; flex-direction: column; gap: 10px; margin: 8px 0; }
.admin-card {
  padding: 14px 16px;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-md);
  background: var(--gray-950);
}
.admin-card .admin-head {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 8px;
  gap: 12px;
}
.admin-card .admin-head .email { font-family: var(--font-primary); font-size: 14px; color: var(--fg-primary); }
.admin-card .admin-head .since { font-family: var(--font-mono); font-size: 10px; color: var(--fg-faint); letter-spacing: 0.1em; }
.admin-grid { display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; align-items: center; }
.admin-grid label { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--fg-faint); }
.admin-grid input, .admin-grid select, .admin-grid textarea {
  background: #000;
  color: var(--fg-body);
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-sm);
  padding: 6px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
}
.admin-grid textarea { resize: vertical; min-height: 50px; }
.admin-actions { display: flex; gap: 8px; margin-top: 10px; }
.admin-flash {
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 50%);
  background: var(--vk-accent-soft);
  color: var(--vk-accent);
  border-radius: var(--radius-md);
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  margin-bottom: 16px;
}

/* ── Bot-token card (admin only) ─────────────────────────────────── */
.bot-token-lede {
  color: var(--fg-muted);
  font-size: 13px;
  line-height: 1.55;
  margin: 0 0 12px;
}
.bot-token-lede code {
  background: var(--gray-850);
  color: var(--fg-secondary);
  padding: 0.05rem 0.3rem;
  border-radius: var(--radius-sm);
  font-size: 0.9em;
}
.bot-token-result {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px dashed var(--border-subtle);
}
.bot-token-meta {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--vk-accent);
  letter-spacing: 0.06em;
  margin-bottom: 6px;
}
.bot-token-jwt {
  width: 100%;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.4;
  color: var(--fg-primary);
  background: var(--gray-950);
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-sm);
  padding: 8px;
  word-break: break-all;
  resize: vertical;
}
.bot-token-error {
  margin-top: 12px;
  padding: 10px 14px;
  border-radius: var(--radius-md);
  border: 1px solid color-mix(in oklab, var(--status-error), transparent 50%);
  background: var(--status-error-bg);
  color: var(--status-error);
  font-family: var(--font-mono);
  font-size: 12px;
}
`);

const SCRIPT = raw(`
(() => {
  // Live UTC clock in the topbar
  const clock = document.getElementById("utc-clock");
  if (clock) {
    const pad = (n) => String(n).padStart(2, "0");
    const fmt = () => {
      const d = new Date();
      return pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " UTC";
    };
    clock.textContent = fmt();
    setInterval(() => { clock.textContent = fmt(); }, 1000);
  }

  // Show the active JWKS kid in the topbar once it loads.
  const kidEl = document.getElementById("jwks-kid");
  if (kidEl) {
    fetch("/api/auth/jwks").then(r => r.json()).then(j => {
      const kid = j && j.keys && j.keys[0] && j.keys[0].kid;
      if (kid) kidEl.textContent = "kid " + String(kid).slice(0, 4);
    }).catch(() => {});
  }

  // Rotating empathy prompt on the signed-out card.
  const empathy = document.getElementById("empathy");
  if (empathy) {
    let prompts = [];
    try { prompts = JSON.parse(empathy.dataset.prompts || "[]"); } catch (_) {}
    const bodyEl = empathy.querySelector(".empathy-body");
    const numEl = empathy.querySelector(".empathy-num");
    const total = prompts.length;
    if (total && bodyEl) {
      let i = Math.floor(Math.random() * total);
      const render = () => {
        bodyEl.textContent = prompts[i];
        if (numEl) numEl.textContent = "Q · " + String(i + 1).padStart(2, "0") + " / " + String(total).padStart(2, "0");
        // re-trigger fade animation
        bodyEl.style.animation = "none";
        // force reflow
        void bodyEl.offsetWidth;
        bodyEl.style.animation = "";
      };
      render();
      setInterval(() => { i = (i + 1) % total; render(); }, 9000);
    }
  }

  // Off-world emigration ticker.
  const ticker = document.getElementById("offworld");
  if (ticker) {
    let pitches = [];
    try { pitches = JSON.parse(ticker.dataset.pitches || "[]"); } catch (_) {}
    const line = ticker.querySelector(".offworld-line");
    if (pitches.length && line) {
      let i = 0;
      line.textContent = pitches[i];
      setInterval(() => {
        i = (i + 1) % pitches.length;
        line.textContent = pitches[i];
      }, 6400);
    }
  }

  // Decoded / raw tabs + copy button on the Subject Profile section.
  const subj = document.getElementById("subject-profile");
  if (subj) {
    const decoded = subj.querySelector("[data-pane='decoded']");
    const rawPane = subj.querySelector("[data-pane='raw']");
    const tabs = subj.querySelectorAll(".claims-tab");
    tabs.forEach(t => t.addEventListener("click", () => {
      tabs.forEach(x => x.classList.remove("is-active"));
      t.classList.add("is-active");
      const which = t.dataset.tab;
      if (decoded) decoded.style.display = which === "decoded" ? "" : "none";
      if (rawPane) rawPane.style.display = which === "raw" ? "" : "none";
    }));
    const copyBtn = subj.querySelector(".claims-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        const text = copyBtn.dataset.claims || "";
        try {
          await navigator.clipboard.writeText(text);
          copyBtn.classList.add("is-copied");
          const orig = copyBtn.textContent;
          copyBtn.textContent = "copied";
          setTimeout(() => {
            copyBtn.classList.remove("is-copied");
            copyBtn.textContent = orig;
          }, 1400);
        } catch (_) {}
      });
    }
  }
})();
`);

// Admin-page-only script. Injected by the /admin handler via a second
// <script> tag after the global SCRIPT (which handles the dashboard
// widgets). Kept separate so the global script doesn't have to query
// for #mint-bot-token on every page.
const ADMIN_BOT_TOKEN_SCRIPT = raw(`
(() => {
  const btn = document.getElementById("mint-bot-token");
  if (!btn) return;
  const result = document.getElementById("bot-token-result");
  const meta = document.getElementById("bot-token-meta");
  const jwt = document.getElementById("bot-token-jwt");
  const copy = document.getElementById("bot-token-copy");
  const clear = document.getElementById("bot-token-clear");
  const err = document.getElementById("bot-token-error");

  const fmtExp = (exp) => {
    const d = new Date(exp * 1000);
    const iso = d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
    const hours = Math.round((exp - Date.now() / 1000) / 360) / 10;
    return iso + " · " + hours + "h from now";
  };

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    err.style.display = "none";
    err.textContent = "";
    try {
      const res = await fetch("/admin/bot-tokens", { method: "POST", credentials: "same-origin" });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || ("HTTP " + res.status));
      }
      meta.textContent = "expires " + fmtExp(body.expires_at) + " · role=admin · purpose=bot";
      jwt.value = body.token;
      result.style.display = "";
    } catch (e) {
      err.textContent = "mint failed: " + (e && e.message ? e.message : String(e));
      err.style.display = "";
    } finally {
      btn.disabled = false;
    }
  });

  copy && copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(jwt.value);
      const orig = copy.textContent;
      copy.textContent = "copied";
      setTimeout(() => { copy.textContent = orig; }, 1400);
    } catch (_) {
      // Fallback: select the textarea so the user can manually copy.
      jwt.select();
    }
  });

  clear && clear.addEventListener("click", () => {
    jwt.value = "";
    meta.textContent = "";
    result.style.display = "none";
  });
})();
`);

// Sibling of ADMIN_BOT_TOKEN_SCRIPT for the service-token card. Kept
// as a second IIFE rather than parameterizing the bot-token script:
// the two cards have distinct ids (`#mint-service-token` vs
// `#mint-bot-token`) and distinct POST targets, and folding them into
// one factory would force the script to know about both UI shapes for
// no real reuse. Easier to ship and easier to delete the service-token
// surface independently if it ever migrates onto the real SA-exchange
// flow.
const ADMIN_SERVICE_TOKEN_SCRIPT = raw(`
(() => {
  const btn = document.getElementById("mint-service-token");
  if (!btn) return;
  const result = document.getElementById("service-token-result");
  const meta = document.getElementById("service-token-meta");
  const jwt = document.getElementById("service-token-jwt");
  const copy = document.getElementById("service-token-copy");
  const clear = document.getElementById("service-token-clear");
  const err = document.getElementById("service-token-error");

  const fmtExp = (exp) => {
    const d = new Date(exp * 1000);
    const iso = d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
    const hours = Math.round((exp - Date.now() / 1000) / 360) / 10;
    return iso + " · " + hours + "h from now";
  };

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    err.style.display = "none";
    err.textContent = "";
    try {
      const res = await fetch("/admin/service-tokens", { method: "POST", credentials: "same-origin" });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || ("HTTP " + res.status));
      }
      meta.textContent = "expires " + fmtExp(body.expires_at) + " · role=service · purpose=bot · actor=" + (body.actor_email || "?");
      jwt.value = body.token;
      result.style.display = "";
    } catch (e) {
      err.textContent = "mint failed: " + (e && e.message ? e.message : String(e));
      err.style.display = "";
    } finally {
      btn.disabled = false;
    }
  });

  copy && copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(jwt.value);
      const orig = copy.textContent;
      copy.textContent = "copied";
      setTimeout(() => { copy.textContent = orig; }, 1400);
    } catch (_) {
      jwt.select();
    }
  });

  clear && clear.addEventListener("click", () => {
    jwt.value = "";
    meta.textContent = "";
    result.style.display = "none";
  });
})();
`);

// ── HTML helpers ──────────────────────────────────────────────────────────

const SHELL = (title: string, body: ReturnType<typeof html>) => html`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&display=swap" />
    <style>${STYLES}</style>
  </head>
  <body>
    <div class="stage">${body}</div>
    ${PYRAMID}
    <script>${SCRIPT}</script>
  </body>
</html>`;

function topbar(status: "online" | "pending" = "online") {
  return html`<header class="topbar">
    <div class="brand">
      <span class="brand-mark">${BRAND_MARK}</span>
      <div class="brand-text">
        <div class="lockup">voight-kampff <span class="dim">/ auth.romaine.life</span></div>
        <div class="division">Tyrell · Authentication Division</div>
      </div>
    </div>
    <div class="topbar-meta">
      <span><span class="dot${status === "pending" ? " is-pending" : ""}"></span> auth.romaine.life · ${status}</span>
      <span class="sep meta-hide-sm">·</span>
      <span class="meta-hide-sm"><span id="jwks-kid">jwks rs256</span></span>
      <span class="sep">·</span>
      <span id="utc-clock">— UTC</span>
    </div>
  </header>`;
}

function footer() {
  return html`<footer class="footer">
    <div class="footer-row">
      <div class="footer-links">
        <a href="/api/auth/jwks">/api/auth/jwks</a>
        <a href="/api/auth/get-session">/api/auth/get-session</a>
        <a href="https://github.com/nelsong6/auth">source</a>
      </div>
      <div class="footer-sigil">NEXUS-7 · BUILD ${BUILD}</div>
    </div>
    <div id="offworld" class="offworld-ticker" aria-live="off" data-pitches="${JSON.stringify(OFFWORLD_PITCHES)}">
      <span class="offworld-tag">OFF-WORLD</span>
      <span class="offworld-line">${OFFWORLD_PITCHES[0]}</span>
    </div>
  </footer>`;
}

// Server-rendered syntax-highlighted JSON. Keys orange, strings mint,
// numbers lavender, booleans clay, punctuation faint. The output is
// HTML so call sites must use `raw()` when embedding.
function prettyClaims(value: unknown): string {
  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const render = (v: unknown, indent: number): string => {
    const pad = "  ".repeat(indent);
    if (v === null) return `<span class="n">null</span>`;
    if (typeof v === "boolean") return `<span class="b">${v}</span>`;
    if (typeof v === "number") return `<span class="n">${v}</span>`;
    if (typeof v === "string") return `<span class="s">"${escape(v)}"</span>`;
    if (Array.isArray(v)) {
      if (v.length === 0) return "[]";
      const inner = v.map((x, i) => `${pad}  ${render(x, indent + 1)}${i < v.length - 1 ? "," : ""}`).join("\n");
      return `[\n${inner}\n${pad}]`;
    }
    if (typeof v === "object") {
      const entries = Object.entries(v as Record<string, unknown>);
      if (entries.length === 0) return "{}";
      const inner = entries
        .map(([k, val], i) => `${pad}  <span class="k">"${escape(k)}"</span><span class="p">:</span> ${render(val, indent + 1)}${i < entries.length - 1 ? "," : ""}`)
        .join("\n");
      return `{\n${inner}\n${pad}}`;
    }
    return String(v);
  };
  return render(value, 0);
}

// Static fake JWT for the "raw" tab — three base64-looking blobs. The header
// and payload are real base64url, the signature is decorative. The real
// JWT is available at /api/auth/token; we don't surface it on the page to
// avoid handing out a copy-pasteable token from the dashboard.
function fakeJwt(claims: Record<string, unknown>): string {
  const b64 = (s: string) => Buffer.from(s).toString("base64url");
  const header = b64(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64(JSON.stringify(claims));
  const sig = "qV1F9b7yK3v2hN8r5sP1xZmL0aW3oI4cT6gQ7B8nE2dM_Y9jK1pR4sV8tU3wX5yA0bC2eF7gH9iJ";
  return `${header}.${payload}.${sig}`.replace(/(.{64})/g, "$1\n");
}

// ── Fixtures + auth-state helper ──────────────────────────────────────────
// In TEST_MODE the handlers return hardcoded fixtures instead of hitting
// Better Auth + the DB. Slot deployments at *.auth.dev.romaine.life run
// in this mode so an operator can cruise the signed-in dashboard without
// any backend.

type AuthState = {
  session: { id: string; createdAt: Date; expiresAt: Date };
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    role?: string;
    apps?: string;
  };
  accounts: Array<{ id: string; providerId: string; createdAt: Date }>;
  sessions: Array<{ id: string; userAgent: string | null; ipAddress: string | null; createdAt: Date }>;
};

const TEST_AUTH_STATE: AuthState = {
  session: {
    id: "s_01",
    createdAt: new Date("2026-05-15T09:42:18Z"),
    expiresAt: new Date("2026-05-22T09:42:18Z"),
  },
  user: {
    id: "usr_9c4f1e8a0d6b",
    name: "Rachael Tyrell",
    email: "rachael@romaine.life",
    emailVerified: true,
    createdAt: new Date("2025-03-14T11:42:18Z"),
    role: "admin",
    apps: JSON.stringify({
      homepage: { theme: "dark" },
      "kill-me": { tdee: 2200 },
      investing: {},
    }),
  },
  accounts: [
    { id: "acc_ms_01", providerId: "microsoft", createdAt: new Date("2025-03-14T11:42:18Z") },
    { id: "acc_g_01", providerId: "google", createdAt: new Date("2025-09-02T08:00:00Z") },
  ],
  sessions: [
    { id: "s_01", userAgent: "Firefox 138 · macOS 14.5", ipAddress: "73.119.84.12", createdAt: new Date("2026-05-15T09:42:00Z") },
    { id: "s_02", userAgent: "Safari 18.4 · iOS 18.4",   ipAddress: "73.119.84.12", createdAt: new Date("2026-05-14T22:08:00Z") },
    { id: "s_03", userAgent: "Chromium 134 · Linux",     ipAddress: "104.28.116.7", createdAt: new Date("2026-05-12T14:11:00Z") },
  ],
};

const TEST_USERS = [
  { id: TEST_AUTH_STATE.user.id, email: "rachael@romaine.life", name: "Rachael Tyrell", role: "admin", apps: TEST_AUTH_STATE.user.apps ?? "{}", emailVerified: true, image: null, createdAt: new Date("2025-03-14T11:42:18Z"), updatedAt: new Date("2026-05-15T09:42:00Z") },
  { id: "usr_a1b2c3d4e5f6", email: "deckard@romaine.life", name: "Rick Deckard", role: "user", apps: "{}", emailVerified: true, image: null, createdAt: new Date("2024-08-01T00:00:00Z"), updatedAt: new Date("2026-05-10T00:00:00Z") },
  { id: "usr_z9y8x7w6v5u4", email: "j.f.sebastian@romaine.life", name: "J.F. Sebastian", role: "pending", apps: "{}", emailVerified: false, image: null, createdAt: new Date("2026-04-22T00:00:00Z"), updatedAt: new Date("2026-04-22T00:00:00Z") },
];

async function getAuthState(c: Context): Promise<AuthState | null> {
  if (TEST_MODE) {
    return isTestSignedIn(c) ? TEST_AUTH_STATE : null;
  }
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!result?.session) return null;
  const userId = result.user.id;
  const accounts = await db.select().from(account).where(eq(account.userId, userId));
  const sessions = await db.select().from(session).where(eq(session.userId, userId)).orderBy(desc(session.createdAt)).limit(5);
  return { session: result.session, user: result.user, accounts, sessions };
}

// ── Routes ────────────────────────────────────────────────────────────────

app.get("/", async (c) => {
  const result = await getAuthState(c);

  if (!result) {
    return c.html(SHELL("Voight-Kampff — auth.romaine.life", html`
      ${topbar("online")}
      <main class="main">
        <div class="vk-card">
          <div class="iris-wrap">${IRIS}</div>
          <h1>Voight-Kampff</h1>
          <p class="subtitle">Empathy Test · Subject Verification</p>
          <p class="lede">
            Examinee not identified. Authenticate to receive an RS256 token signed by this service; all <code>*.romaine.life</code> apps verify against this <code>jwks</code>.
          </p>
          <p class="epigraph">"more human than human" — Tyrell, 2019</p>

          <div id="empathy" class="empathy-prompt" data-prompts="${JSON.stringify(EMPATHY_PROMPTS)}">
            <div class="empathy-head">
              <span class="empathy-num">Q · 01 / ${String(EMPATHY_PROMPTS.length).padStart(2, "0")}</span>
              <span>probe pre-roll · sample question</span>
            </div>
            <p class="empathy-body">${EMPATHY_PROMPTS[0]}</p>
          </div>

          <div class="signin-stack">
            <form class="signin-form" method="POST" action="/sign-in/microsoft">
              <button class="signin-btn" type="submit">
                ${MSFT_LOGO}
                <span class="signin-label">Sign in with Microsoft</span>
                <span class="signin-meta">entra</span>
              </button>
            </form>
            <form class="signin-form" method="POST" action="/sign-in/google">
              <button class="signin-btn" type="submit">
                ${GOOGLE_LOGO}
                <span class="signin-label">Sign in with Google</span>
                <span class="signin-meta">oidc</span>
              </button>
            </form>
          </div>

          <p class="vk-footnote">
            session scoped to <code>.romaine.life</code> · sso across every subdomain
          </p>
        </div>
      </main>
      ${footer()}
    `));
  }

  const u = result.user;
  const accounts = result.accounts;
  const sessions = result.sessions;

  const role = (u as { role?: string }).role ?? "user";
  const appsBlob = (() => {
    try { return JSON.parse((u as { apps?: string }).apps ?? "{}") as Record<string, unknown>; }
    catch { return {} as Record<string, unknown>; }
  })();
  const claims = {
    iss: process.env.BASE_URL ?? "https://auth.romaine.life",
    sub: u.id,
    aud: "romaine.life",
    iat: Math.floor(result.session.createdAt.getTime() / 1000),
    exp: Math.floor(result.session.expiresAt.getTime() / 1000),
    email: u.email,
    name: u.name,
    email_verified: u.emailVerified,
    role,
    apps: appsBlob,
  };

  const currentSessionId = result.session.id;
  const grantedCount = ROMAINE_APPS.filter((a) => a.name in appsBlob).length;
  const createdAt = u.createdAt instanceof Date ? u.createdAt : new Date(u.createdAt);
  const nexusInc = createdAt.toISOString().slice(0, 10).split("-").reverse().join("·").toUpperCase();
  // short, stable per-user designation: first 3 alpha chars of the name +
  // first 3 chars of the user id. Falls back if anything's missing.
  const nameSlug = (u.name || "subject").replace(/[^A-Za-z]/g, "").slice(0, 3).toUpperCase().padEnd(3, "X");
  const idSlug = u.id.replace(/-/g, "").slice(0, 3).toUpperCase().padEnd(3, "0");
  const nexusId = `EXP·${nameSlug}-${idSlug}`;

  const roleLabel = role === "admin" ? "Blade Runner" : role === "pending" ? "Awaiting Review" : "Citizen";
  const roleClass = role === "admin" ? "is-admin" : role === "pending" ? "is-pending" : "";

  return c.html(SHELL(`${u.name} — Voight-Kampff`, html`
    ${topbar("online")}
    <main class="main">
      <div class="dash">
        <section class="dash-head">
          <div class="iris-mini-wrap">${IRIS_MINI}</div>
          <div class="head-text">
            <div class="head-name">${u.name}</div>
            <div class="head-email">${u.email} · ${u.id}</div>
            <div class="head-designation">
              <span class="nexus-tag">NEXUS-7</span>
              <span class="nexus-id">${nexusId}</span>
              <span class="nexus-sep">·</span>
              <span>inc. ${nexusInc}</span>
            </div>
            <div class="head-status">
              <span class="blink-dot"></span>
              ${role === "pending"
                ? raw(`awaiting blade-runner review`)
                : raw(`subject verified · empathy confirmed`)}
            </div>
          </div>
          <div class="head-aside">
            <span class="role-badge ${roleClass}"><span class="dot"></span>${roleLabel}</span>
            ${role === "admin"
              ? html`<a class="admin-btn" href="/admin">Tyrell Console</a>`
              : html``}
            <form class="signout-form" method="POST" action="/sign-out">
              <button class="end-btn" type="submit">End interview</button>
            </form>
          </div>
        </section>

        ${role === "pending" ? html`
          <div class="pending-callout">
            Authentication accepted, but the registry does not yet recognize you as a romaine.life subject. A blade runner must promote your status before downstream apps will admit you.
          </div>
        ` : html``}

        <div class="dash-grid">
          <section class="section">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Provenance</span>
              <span class="count">${accounts.length} linked</span>
            </div>
            <div class="section-body">
              ${accounts.length === 0
                ? html`<div class="empty">no linked accounts</div>`
                : accounts.map((a, i) => html`
                  <div class="row">
                    <span class="row-icon">${a.providerId === "microsoft" ? MSFT_LOGO : a.providerId === "google" ? GOOGLE_LOGO : KEY_ICON}</span>
                    <div class="row-main">
                      <div class="row-primary">${a.providerId}</div>
                      <div class="row-secondary">enrolled ${a.createdAt.toISOString().slice(0, 10)} · provider · ${a.providerId}</div>
                    </div>
                    <span class="pill${i === 0 ? " current" : ""}">${i === 0 ? "primary" : "linked"}</span>
                  </div>
                `)}
            </div>
          </section>

          <section class="section">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Prior Interrogations</span>
              <span class="count">${sessions.length} active</span>
            </div>
            <div class="section-body">
              ${sessions.length === 0
                ? html`<div class="empty">no recorded sessions</div>`
                : sessions.map((s) => html`
                  <div class="row">
                    <span class="row-icon">${CLOCK_ICON}</span>
                    <div class="row-main">
                      <div class="row-primary">${s.createdAt.toISOString().replace("T", " ").slice(0, 16)} UTC${s.id === currentSessionId ? "  ·  this session" : ""}</div>
                      <div class="row-secondary">${s.userAgent ?? "—"}${s.ipAddress ? ` · ${s.ipAddress}` : ""}</div>
                    </div>
                    ${s.id === currentSessionId
                      ? html`<span class="pill current">current</span>`
                      : html`<span class="pill">past</span>`}
                  </div>
                `)}
            </div>
          </section>

          <section class="section col-span-2">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Authorized Modules</span>
              <span class="count">${grantedCount} of ${ROMAINE_APPS.length} subdomains</span>
            </div>
            <div class="apps">
              ${ROMAINE_APPS.map((a) => {
                const granted = a.name in appsBlob;
                const prefVal = appsBlob[a.name];
                const prefCount = prefVal && typeof prefVal === "object" && !Array.isArray(prefVal)
                  ? Object.keys(prefVal as Record<string, unknown>).length
                  : 0;
                return html`
                  <a class="app-tile${granted ? " granted" : ""}" href="https://${a.host}">
                    <span class="app-name">${a.name}</span>
                    <span class="app-host"><strong>${a.host.split(".")[0]}</strong>.romaine.life</span>
                    <div class="app-foot">
                      <span class="${granted ? "ok" : ""}">${granted ? "● granted" : "○ no prefs"}</span>
                      <span>${prefCount || "—"} prefs</span>
                    </div>
                  </a>
                `;
              })}
            </div>
          </section>

          <section id="subject-profile" class="section col-span-2">
            <div class="section-head">
              <span class="title">
                <span class="sigil">//</span>Subject Profile
                <span class="meta">token claims surfaced to romaine.life apps</span>
              </span>
              <span class="claims-tabs">
                <button class="claims-tab is-active" data-tab="decoded">decoded</button>
                <button class="claims-tab" data-tab="raw">raw</button>
                <button class="claims-copy" data-claims="${JSON.stringify(claims, null, 2)}">copy</button>
              </span>
            </div>
            <div class="claims-wrap">
              <pre class="claims" data-pane="decoded">${raw(prettyClaims(claims))}</pre>
              <pre class="claims" data-pane="raw" style="display:none">${fakeJwt(claims)}</pre>
            </div>
          </section>
        </div>
      </div>
    </main>
    ${footer()}
  `));
});

// ── Admin console ──────────────────────────────────────────────────────────
// Single-page user manager — role + per-app `apps` JSON blob, plus name.
// Source of truth for the platform-wide admin list (formerly the
// `romaine-life-admin-emails` KV secret). Gated on role=admin claim.

// Issuer the admin bearer path pins, matching the romaine-auth-py verifier
// contract (AUTH_ROMAINE_LIFE_ISSUER, default https://auth.romaine.life).
// Audience is intentionally not pinned — every auth.romaine.life token
// carries aud=issuer, so it adds no per-app isolation (same rationale as
// romaine-auth-py).
const ADMIN_BEARER_ISSUER = (process.env.BASE_URL ?? "https://auth.romaine.life").replace(/\/$/, "");

// Resolve our live JWKS in-process and verify a role=admin bearer token
// against it. getJwks() reads the key set from the DB each call (admin
// traffic is low) so a key rotation is picked up without a restart. The
// verification contract lives in src/admin-bearer.ts.
async function verifyAdminBearer(token: string) {
  const jwks = (await auth.api.getJwks()) as JSONWebKeySet;
  return verifyAdminBearerJwt(token, jwks, ADMIN_BEARER_ISSUER);
}

async function requireAdmin(c: Context) {
  if (TEST_MODE) {
    if (!isTestSignedIn(c)) return { status: 302 as const, location: "/" };
    return { ok: true as const, user: TEST_AUTH_STATE.user };
  }
  // 1. Browser session (cookie) — the /admin console path.
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (result?.session) {
    const role = (result.user as { role?: string }).role ?? "user";
    if (role !== "admin") return { status: 403 as const };
    return { ok: true as const, user: result.user };
  }
  // 2. Bearer JWT — the machine/API path. mcp-auth forwards the caller's
  //    auth.romaine.life JWT here, and an admin can call directly with an
  //    authromaine bot token. A present-but-invalid token is a 403 (a
  //    deliberate, failed attempt), not a 302 redirect to the login page.
  const authz = c.req.header("Authorization");
  if (authz?.startsWith("Bearer ")) {
    try {
      const claims = await verifyAdminBearer(authz.slice("Bearer ".length).trim());
      return {
        ok: true as const,
        user: {
          id: typeof claims.sub === "string" ? claims.sub : "",
          email: typeof claims.email === "string" ? claims.email : "",
          name: typeof claims.name === "string" ? claims.name : "",
          role: "admin" as const,
        },
      };
    } catch {
      return { status: 403 as const };
    }
  }
  return { status: 302 as const, location: "/" };
}

app.get("/admin", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) {
    if (gate.status === 302) return c.redirect(gate.location);
    return c.text("forbidden", 403);
  }
  const users = TEST_MODE ? TEST_USERS : await db.select().from(user).orderBy(desc(user.createdAt));
  const flash = c.req.query("ok") ?? (TEST_MODE ? "test mode · changes are discarded" : null);
  return c.html(SHELL("Tyrell Console — Subjects", html`
    ${topbar("online")}
    <main class="main">
      <div class="dash">
        <section class="dash-head">
          <div class="iris-mini-wrap">${IRIS_MINI}</div>
          <div class="head-text">
            <div class="head-name">Subject Registry</div>
            <div class="head-email">Authenticate · Classify · Retire</div>
            <div class="head-designation">
              <span class="nexus-tag">CONSOLE</span>
              <span class="nexus-id">OPERATIONS</span>
            </div>
          </div>
          <div class="head-aside">
            <a class="admin-btn" href="/">← Dashboard</a>
          </div>
        </section>

        ${flash ? html`<div class="admin-flash">${flash}</div>` : html``}

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Active Subjects</span>
            <span class="count">${users.length} on file</span>
          </div>
          <div class="section-body">
            ${users.length === 0
              ? html`<div class="empty">no subjects on file</div>`
              : html`<div class="admin-list">
                ${users.map((u) => html`
                  <form class="admin-card" method="POST" action="/admin/users/${u.id}">
                    <div class="admin-head">
                      <span class="email">${u.email}</span>
                      <span class="since">${u.createdAt.toISOString().slice(0, 10)}</span>
                    </div>
                    <div class="admin-grid">
                      <label>Name</label>
                      <input name="name" value="${u.name}" />
                      <label>Role</label>
                      <select name="role">
                        <option value="user" ${u.role === "user" ? "selected" : ""}>citizen</option>
                        <option value="admin" ${u.role === "admin" ? "selected" : ""}>blade runner</option>
                      </select>
                      <label>Apps</label>
                      <textarea name="apps" rows="2">${u.apps}</textarea>
                    </div>
                    <div class="admin-actions">
                      <button class="admin-btn" type="submit">Update</button>
                    </div>
                  </form>
                `)}
              </div>`}
          </div>
        </section>

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Enroll Subject</span>
            <span class="count">pre-create row</span>
          </div>
          <div class="section-body">
            <form class="admin-card" method="POST" action="/admin/users">
              <div class="admin-grid">
                <label>Email</label>
                <input name="email" required placeholder="subject@example.com" />
                <label>Name</label>
                <input name="name" placeholder="Display name" />
                <label>Role</label>
                <select name="role">
                  <option value="user">citizen</option>
                  <option value="admin">blade runner</option>
                </select>
              </div>
              <div class="admin-actions">
                <button class="admin-btn" type="submit">Enroll</button>
              </div>
            </form>
          </div>
        </section>

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Bot token</span>
            <span class="count">24h · role=admin · purpose=bot</span>
          </div>
          <div class="section-body">
            <div class="admin-card" id="bot-token-card">
              <p class="bot-token-lede">
                Break-glass JWT for <code>Authorization: Bearer …</code> from
                outside the browser — typically to salvage tank-operator state
                when the chat UI is down. Pasteable into <code>curl</code>;
                expires in 24h. To revoke before then,
                <code>az keyvault key rotate auth-jwt-signing</code> rolls the
                signing key and invalidates every outstanding
                auth.romaine.life JWT.
              </p>
              <div class="admin-actions">
                <button class="admin-btn" id="mint-bot-token">Mint bot token</button>
              </div>
              <div class="bot-token-result" id="bot-token-result" style="display:none">
                <div class="bot-token-meta" id="bot-token-meta"></div>
                <textarea class="bot-token-jwt" id="bot-token-jwt" readonly rows="6"></textarea>
                <div class="admin-actions">
                  <button class="admin-btn" id="bot-token-copy" type="button">Copy</button>
                  <button class="admin-btn" id="bot-token-clear" type="button">Clear</button>
                </div>
              </div>
              <div class="bot-token-error" id="bot-token-error" style="display:none"></div>
            </div>
          </div>
        </section>

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Service token</span>
            <span class="count">24h · role=service · purpose=bot</span>
          </div>
          <div class="section-body">
            <div class="admin-card" id="service-token-card">
              <p class="bot-token-lede">
                Sibling to the bot token, but issued with
                <code>role=service</code> and
                <code>actor_email=&lt;your email&gt;</code> so the JWT passes the
                verifier contract that
                <code>mcp-github</code> (and other service-only MCPs) pin on.
                Use when you need to call those MCPs from a workstation
                without setting up the full k8s service-account exchange.
                Same revocation path as the bot token —
                <code>az keyvault key rotate auth-jwt-signing</code>.
              </p>
              <div class="admin-actions">
                <button class="admin-btn" id="mint-service-token">Mint service token</button>
              </div>
              <div class="bot-token-result" id="service-token-result" style="display:none">
                <div class="bot-token-meta" id="service-token-meta"></div>
                <textarea class="bot-token-jwt" id="service-token-jwt" readonly rows="6"></textarea>
                <div class="admin-actions">
                  <button class="admin-btn" id="service-token-copy" type="button">Copy</button>
                  <button class="admin-btn" id="service-token-clear" type="button">Clear</button>
                </div>
              </div>
              <div class="bot-token-error" id="service-token-error" style="display:none"></div>
            </div>
          </div>
        </section>
      </div>
    </main>
    ${footer()}
    <script>${ADMIN_BOT_TOKEN_SCRIPT}</script>
    <script>${ADMIN_SERVICE_TOKEN_SCRIPT}</script>
  `));
});

// Bot-token mint. Admin-only, 24h TTL, stamped with purpose="bot" so
// downstream audit logs can distinguish bot mints from browser sign-ins.
// Same signing key as the cookie/exchange paths — any verifier that
// already accepts an auth.romaine.life JWT accepts this one with no
// change. Revocation before natural expiry is `az keyvault key rotate
// auth-jwt-signing` (rolls the signing key, invalidates every outstanding
// JWT including the cookie tokens; acceptable cost for the rare-event
// bot-token surface).
const BOT_TOKEN_TTL_SECONDS = 24 * 60 * 60;

type BotTokenUser = {
  id: string;
  email: string;
  name: string;
  apps?: string;
};

async function mintAdminBotToken(
  u: BotTokenUser,
  source: "admin-console" | "cli-device",
): Promise<{
  token: string;
  expires_at: number;
  expires_in_hours: number;
  purpose: "bot";
}> {
  let apps: Record<string, unknown> = {};
  try {
    apps = JSON.parse(u.apps ?? "{}");
  } catch {
    // Bad JSON in the apps column shouldn't block a bot-token mint.
    apps = {};
  }

  const signed = await mintAuthJwt({
    sub: u.id,
    email: u.email,
    name: u.name,
    role: "admin",
    apps,
    purpose: "bot",
    ttlSeconds: BOT_TOKEN_TTL_SECONDS,
  });

  recordAdminBotTokenMint();
  console.warn(
    source === "admin-console" ? "[/admin/bot-tokens] minted:" : "[/api/cli/token] minted:",
    JSON.stringify({ email: u.email, exp: signed.exp, purpose: "bot", source }),
  );

  return {
    token: signed.token,
    expires_at: signed.exp,
    expires_in_hours: 24,
    purpose: "bot",
  };
}

app.post("/admin/bot-tokens", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) {
    return c.json({ error: "admin only" }, gate.status === 302 ? 401 : 403);
  }
  if (TEST_MODE) {
    // Test slots have no JWKS / signing key — return a placeholder so the
    // UI button still demonstrates the flow without standing up Better Auth.
    return c.json({
      token: "test-mode-bot-token-placeholder",
      expires_at: Math.floor(Date.now() / 1e3) + BOT_TOKEN_TTL_SECONDS,
      expires_in_hours: 24,
      purpose: "bot",
    });
  }

  const u = gate.user as typeof gate.user & { role?: string; apps?: string };
  try {
    return c.json(await mintAdminBotToken(u, "admin-console"));
  } catch (e) {
    console.error("[/admin/bot-tokens] mintAuthJwt failed:", e);
    return c.json({ error: "failed to mint token" }, 500);
  }
});

// Service-token mint. Sibling of /admin/bot-tokens above, but produces
// a `role=service` JWT carrying `actor_email=<admin's email>` so it
// passes the verifier contract that mcp-github (and any future
// service-only MCP) enforces:
//
//     role == "service"  AND  actor_email is non-empty
//
// The admin's user row itself is unchanged — `sub`, `email`, and `name`
// on the JWT remain the admin's identity, while `role=service` +
// `actor_email=<admin email>` make the token a self-actor service
// principal. The semantic is "the admin is acting as a service
// principal on their own behalf" — the human-and-machine in this
// break-glass surface are the same person, and `actor_email` carries
// the audit trail downstream consumers want.
//
// This intentionally does NOT route through the k8s service-exchange
// flow in src/service-exchange.ts: that flow exists for pods whose
// identity comes from a projected SA token and whose actor is encoded
// in pod annotations. An admin at a workstation has neither, and the
// SA-exchange's synthetic-email/pod-lineage machinery would be
// machinery-for-machinery's-sake here. If a future use case wants a
// long-lived service identity for a named admin (separate user row,
// reusable `sub`, etc.), the right move is to extend
// `service-exchange.ts` with a `mode: "admin-bot"` consumer rather
// than evolve this surface.
const SERVICE_TOKEN_TTL_SECONDS = 24 * 60 * 60;

app.post("/admin/service-tokens", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) {
    return c.json({ error: "admin only" }, gate.status === 302 ? 401 : 403);
  }
  if (TEST_MODE) {
    // Test slots have no JWKS / signing key — return a placeholder so the
    // UI button still demonstrates the flow without standing up Better Auth.
    return c.json({
      token: "test-mode-service-token-placeholder",
      expires_at: Math.floor(Date.now() / 1e3) + SERVICE_TOKEN_TTL_SECONDS,
      expires_in_hours: 24,
      purpose: "bot",
      role: "service",
      actor_email: (gate.user as { email?: string }).email ?? "test@romaine.life",
    });
  }

  const u = gate.user as typeof gate.user & { role?: string; apps?: string };
  // Service tokens conventionally carry an empty `apps` claim — per-app
  // prefs are a human concept and a service principal has none. Mirrors
  // the service-exchange flow in src/service-exchange.ts, which also
  // passes `apps: {}` for the same reason.

  let signed;
  try {
    signed = await mintAuthJwt({
      sub: u.id,
      email: u.email,
      name: u.name,
      role: "service",
      apps: {},
      actorEmail: u.email,
      purpose: "bot",
      ttlSeconds: SERVICE_TOKEN_TTL_SECONDS,
    });
  } catch (e) {
    console.error("[/admin/service-tokens] mintAuthJwt failed:", e);
    return c.json({ error: "failed to mint token" }, 500);
  }

  recordAdminServiceTokenMint();
  // Structured per-mint audit line. Same shape as the bot-token mint's
  // audit line, plus the actor_email claim (which equals the admin's
  // own email here — kept explicit so a future change that decouples
  // actor from caller will surface in the log diff). `purpose=bot` is
  // intentional: it tells downstream audit pipelines that this is a
  // human-minted convenience token, not a pod-issued exchange token.
  console.warn(
    "[/admin/service-tokens] minted:",
    JSON.stringify({
      email: u.email,
      actor_email: u.email,
      exp: signed.exp,
      role: "service",
      purpose: "bot",
    }),
  );

  return c.json({
    token: signed.token,
    expires_at: signed.exp,
    expires_in_hours: 24,
    purpose: "bot",
    role: "service",
    actor_email: u.email,
  });
});

app.post("/admin/users", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  if (TEST_MODE) return c.redirect("/admin?ok=test+mode+%C2%B7+enroll+discarded");
  const form = await c.req.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const name = String(form.get("name") ?? "").trim() || email;
  const role = String(form.get("role") ?? "user");
  if (!email || !email.includes("@")) return c.text("invalid email", 400);
  if (role !== "admin" && role !== "user") return c.text("invalid role", 400);
  if (isReservedServiceEmail(email)) {
    // Admin console must not create human users under the service-principal
    // reserved domains — collision with a real exchange would point two
    // different intents (admin enrollment vs SA exchange) at the same row.
    // Service principals are minted exclusively by /api/auth/exchange/k8s.
    return c.text("email is in a reserved service-principal domain", 400);
  }
  // Pre-create the row. Better Auth's Microsoft social provider matches on
  // email when the user signs in for the first time, so the row will gain
  // emailVerified=true + the Microsoft account link at that point.
  const id = crypto.randomUUID();
  try {
    await db.insert(user).values({ id, email, name, role, emailVerified: false });
  } catch (err) {
    console.error("[admin/users] insert failed:", err);
    return c.text("insert failed (email likely already exists)", 400);
  }
  return c.redirect(`/admin?ok=enrolled+${encodeURIComponent(email)}`);
});

app.post("/admin/users/:id", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  if (TEST_MODE) return c.redirect("/admin?ok=test+mode+%C2%B7+update+discarded");
  const id = c.req.param("id");
  const form = await c.req.formData();
  const name = String(form.get("name") ?? "").trim();
  const role = String(form.get("role") ?? "user");
  const apps = String(form.get("apps") ?? "{}");
  if (!name) return c.text("name required", 400);
  if (role !== "admin" && role !== "user") return c.text("invalid role", 400);
  try {
    JSON.parse(apps);
  } catch {
    return c.text("apps must be valid JSON", 400);
  }
  await db.update(user)
    .set({ name, role, apps, updatedAt: new Date() })
    .where(eq(user.id, id));
  return c.redirect("/admin?ok=updated");
});

type CliDeviceGrantRow = typeof cliDeviceGrant.$inferSelect;

async function readJsonObject(c: Context): Promise<Record<string, unknown>> {
  const text = await c.req.text();
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("invalid JSON body");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("JSON body must be an object");
  }
  return parsed as Record<string, unknown>;
}

function publicBaseUrl(c: Context): string {
  return (process.env.BASE_URL ?? new URL(c.req.url).origin).replace(/\/$/, "");
}

function cliGrantExpired(grant: CliDeviceGrantRow): boolean {
  return grant.expiresAt.getTime() <= Date.now();
}

async function markCliGrantExpired(grant: CliDeviceGrantRow): Promise<void> {
  if (grant.status === "pending" || grant.status === "approved") {
    await db
      .update(cliDeviceGrant)
      .set({ status: "expired" satisfies CliDeviceStatus })
      .where(eq(cliDeviceGrant.id, grant.id));
  }
}

async function findCliGrantByUserCode(userCode: string): Promise<CliDeviceGrantRow | null> {
  const rows = await db
    .select()
    .from(cliDeviceGrant)
    .where(eq(cliDeviceGrant.userCodeHash, hashSecret(normalizeUserCode(userCode))))
    .limit(1);
  return rows[0] ?? null;
}

async function findCliGrantByDeviceCode(deviceCode: string): Promise<CliDeviceGrantRow | null> {
  const rows = await db
    .select()
    .from(cliDeviceGrant)
    .where(eq(cliDeviceGrant.deviceCodeHash, hashSecret(deviceCode)))
    .limit(1);
  return rows[0] ?? null;
}

async function findCliGrantByExchangeCode(code: string): Promise<CliDeviceGrantRow | null> {
  const rows = await db
    .select()
    .from(cliDeviceGrant)
    .where(eq(cliDeviceGrant.exchangeCodeHash, hashSecret(code)))
    .limit(1);
  return rows[0] ?? null;
}

async function listPreviousCliMiscIdentifiers(): Promise<string[]> {
  const rows = await db
    .select({ clientName: cliDeviceGrant.clientName })
    .from(cliDeviceGrant)
    .orderBy(desc(cliDeviceGrant.createdAt))
    .limit(250);
  return previousMiscIdentifiersFromClientNames(rows.map((row) => row.clientName));
}

function oauthError(c: Context, error: string, status = 400, extra: Record<string, unknown> = {}) {
  return c.json({ error, ...extra }, status as Parameters<typeof c.json>[1]);
}

function cliStatusMessage(grant: CliDeviceGrantRow | null): string {
  if (!grant) return "No pending request matches that code.";
  if (cliGrantExpired(grant)) return "That request expired. Ask the requester to start a new bot-token request.";
  if (grant.status === "pending") return "Review the request below before approving.";
  if (grant.status === "approved") return "That request was already approved.";
  if (grant.status === "consumed") return "That request has already been exchanged for a bot token.";
  if (grant.status === "denied") return "That request was denied.";
  return "That request expired. Ask the requester to start a new bot-token request.";
}

function cliApprovedMessage(grant: CliDeviceGrantRow): string {
  const requester = decodeRequesterInfo(grant.clientName);
  return `Approved. The requester identified as "${requester.miscIdentifier}" can now exchange this request for a bot token.`;
}

function cliApprovalPage(opts: {
  userCode: string;
  grant: CliDeviceGrantRow | null;
  message: string;
  callbackUrl?: string | null;
  exchangeCode?: string | null;
}) {
  const grant = opts.grant;
  const requester = grant ? decodeRequesterInfo(grant.clientName) : null;
  return SHELL("Approve CLI token - auth.romaine.life", html`
    ${topbar("online")}
    <main class="main">
      <div class="vk-card">
        <div class="iris-wrap">${IRIS}</div>
        <h1>CLI token approval</h1>
        <p class="subtitle">Bot token request</p>
        <p class="lede">${opts.message}</p>

        ${!grant && !opts.exchangeCode ? html`
          <form class="admin-card" method="GET" action="/cli">
            <div class="admin-grid">
              <label>Code</label>
              <input name="user_code" value="${opts.userCode}" placeholder="VK-ABCD-1234" />
            </div>
            <div class="admin-actions">
              <button class="admin-btn" type="submit">Review request</button>
            </div>
          </form>
        ` : html``}

        ${grant ? html`
          <div class="admin-card">
            <div class="admin-head">
              <span class="email">Requester</span>
              <span class="since">${grant.expiresAt.toISOString().slice(11, 16)} UTC</span>
            </div>
            <div class="admin-grid">
              <label>Where</label>
              <textarea readonly rows="5">${requester?.whereHappening ?? ""}</textarea>
              <label>Intended use</label>
              <textarea readonly rows="5">${requester?.intendedUse ?? ""}</textarea>
              <label>Misc identifier</label>
              <input readonly value="${requester?.miscIdentifier ?? ""}" />
              <label>User code</label>
              <input readonly value="${opts.userCode}" />
              <label>Status</label>
              <input readonly value="${grant.status}" />
              <label>Return URL</label>
              <input readonly value="${grant.redirectUri ?? "none"}" />
            </div>
          </div>
        ` : html``}

        ${grant && grant.status === "pending" && !cliGrantExpired(grant) ? html`
          <form class="signin-stack" method="POST" action="/cli/approve">
            <input type="hidden" name="user_code" value="${opts.userCode}" />
            <button class="signin-btn" type="submit" name="decision" value="approve">
              <span class="signin-label">Approve bot token</span>
              <span class="signin-meta">24h</span>
            </button>
            <button class="signin-btn" type="submit" name="decision" value="deny">
              <span class="signin-label">Deny request</span>
              <span class="signin-meta">cancel</span>
            </button>
          </form>
        ` : html``}

        ${opts.exchangeCode ? html`
          <div class="bot-token-result" style="display:block">
            <div class="bot-token-meta">One-time fallback code</div>
            <textarea class="bot-token-jwt" readonly rows="3">${opts.exchangeCode}</textarea>
          </div>
        ` : html``}

        ${opts.callbackUrl ? html`
          <p class="vk-footnote">
            The requester should finish through device polling. If it does not,
            paste the fallback code into the requesting app or use the return link.
          </p>
          <p class="vk-footnote"><a href="${opts.callbackUrl}">Return to application</a></p>
        ` : html``}
      </div>
    </main>
    ${footer()}
  `);
}

app.get("/api/cli/requester-guidance", async (c) => {
  return c.json(buildRequesterGuidance(await listPreviousCliMiscIdentifiers()));
});

app.post("/api/cli/device", async (c) => {
  if (TEST_MODE) return c.json({ error: "cli device flow unavailable in test mode" }, 404);

  let body: Record<string, unknown>;
  try {
    body = await readJsonObject(c);
  } catch (e) {
    return c.json({ error: (e as Error).message }, 400);
  }

  let redirectUri: string | null;
  let pkce: { codeChallenge: string | null; codeChallengeMethod: "S256" | null };
  let requesterInfo: CliRequesterInfo;
  try {
    redirectUri = validateLoopbackRedirectUri(body.redirect_uri);
    pkce = validatePkceInput(
      redirectUri,
      body.code_challenge,
      body.code_challenge_method,
    );
    requesterInfo = requireRequesterInfo(body);
  } catch (e) {
    return c.json({ error: (e as Error).message }, 400);
  }

  const deviceCode = randomUrlToken();
  const userCode = generateUserCode();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CLI_DEVICE_EXPIRES_SECONDS * 1000);
  const verificationUri = `${publicBaseUrl(c)}/cli`;
  await db.insert(cliDeviceGrant).values({
    id: crypto.randomUUID(),
    deviceCodeHash: hashSecret(deviceCode),
    userCodeHash: hashSecret(normalizeUserCode(userCode)),
    clientName: encodeRequesterInfo(requesterInfo),
    redirectUri,
    state: typeof body.state === "string" ? body.state.slice(0, 500) : null,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: pkce.codeChallengeMethod,
    status: "pending" satisfies CliDeviceStatus,
    createdAt: now,
    expiresAt,
  });

  return c.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(userCode)}`,
    expires_in: CLI_DEVICE_EXPIRES_SECONDS,
    interval: CLI_DEVICE_POLL_INTERVAL_SECONDS,
  });
});

app.get("/cli", async (c) => {
  const rawUserCode = c.req.query("user_code") ?? "";
  const userCode = rawUserCode.trim();
  if (!userCode) {
    return c.html(cliApprovalPage({
      userCode: "",
      grant: null,
      message: "Enter the code shown by the requester to approve a bot-token request.",
    }));
  }

  const gate = await requireAdmin(c);
  if ("status" in gate) {
    if (gate.status === 403) return c.text("forbidden", 403);
    return c.redirect(`/sign-in/microsoft?callbackURL=${encodeURIComponent(`/cli?user_code=${userCode}`)}`);
  }

  const grant = await findCliGrantByUserCode(userCode);
  if (grant && cliGrantExpired(grant)) await markCliGrantExpired(grant);
  return c.html(cliApprovalPage({
    userCode,
    grant,
    message: cliStatusMessage(grant),
  }));
});

app.post("/cli/approve", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  if (TEST_MODE) return c.text("cli device flow unavailable in test mode", 404);

  const form = await c.req.formData();
  const userCode = String(form.get("user_code") ?? "").trim();
  const decision = String(form.get("decision") ?? "");
  if (!userCode) return c.text("missing user_code", 400);
  if (decision !== "approve" && decision !== "deny") return c.text("invalid decision", 400);

  const grant = await findCliGrantByUserCode(userCode);
  if (!grant) {
    return c.html(cliApprovalPage({
      userCode,
      grant: null,
      message: "No pending request matches that code.",
    }), 404);
  }
  if (cliGrantExpired(grant)) {
    await markCliGrantExpired(grant);
    return c.html(cliApprovalPage({
      userCode,
      grant,
      message: "That request expired. Ask the requester to start a new bot-token request.",
    }), 400);
  }
  if (grant.status !== "pending") {
    return c.html(cliApprovalPage({
      userCode,
      grant,
      message: cliStatusMessage(grant),
    }), 409);
  }

  if (decision === "deny") {
    const updated = await db
      .update(cliDeviceGrant)
      .set({ status: "denied" satisfies CliDeviceStatus })
      .where(and(eq(cliDeviceGrant.id, grant.id), eq(cliDeviceGrant.status, "pending")))
      .returning();
    if (updated.length === 0) {
      const latest = await findCliGrantByUserCode(userCode);
      return c.html(cliApprovalPage({
        userCode,
        grant: latest,
        message: cliStatusMessage(latest),
      }), 409);
    }
    return c.html(cliApprovalPage({
      userCode,
      grant: updated[0],
      message: "Request denied.",
    }));
  }

  const exchangeCode = randomUrlToken();
  const u = gate.user as typeof gate.user & { role?: string };
  const updated = await db
    .update(cliDeviceGrant)
    .set({
      status: "approved" satisfies CliDeviceStatus,
      exchangeCodeHash: hashSecret(exchangeCode),
      approvedByUserId: u.id,
      approvedByEmail: u.email,
      approvedAt: new Date(),
    })
    .where(and(eq(cliDeviceGrant.id, grant.id), eq(cliDeviceGrant.status, "pending")))
    .returning();
  if (updated.length === 0) {
    const latest = await findCliGrantByUserCode(userCode);
    return c.html(cliApprovalPage({
      userCode,
      grant: latest,
      message: cliStatusMessage(latest),
    }), 409);
  }
  const approved = updated[0];
  const callbackUrl = approved.redirectUri
    ? appendCallbackParams(approved.redirectUri, exchangeCode, approved.state)
    : null;
  return c.html(cliApprovalPage({
    userCode,
    grant: approved,
    message: cliApprovedMessage(approved),
    callbackUrl,
    exchangeCode,
  }));
});

async function consumeApprovedCliGrant(c: Context, grant: CliDeviceGrantRow) {
  if (cliGrantExpired(grant)) {
    await markCliGrantExpired(grant);
    return oauthError(c, "expired_token");
  }
  if (grant.status === "pending") {
    return oauthError(c, "authorization_pending", 400, {
      interval: CLI_DEVICE_POLL_INTERVAL_SECONDS,
    });
  }
  if (grant.status === "denied") return oauthError(c, "access_denied");
  if (grant.status === "consumed") return oauthError(c, "invalid_grant");
  if (grant.status !== "approved") return oauthError(c, "expired_token");
  if (!grant.approvedByUserId) return oauthError(c, "invalid_grant");

  const rows = await db
    .select()
    .from(user)
    .where(eq(user.id, grant.approvedByUserId))
    .limit(1);
  const approver = rows[0];
  if (!approver || approver.role !== "admin") return oauthError(c, "access_denied", 403);

  const consumed = await db
    .update(cliDeviceGrant)
    .set({ status: "consumed" satisfies CliDeviceStatus, consumedAt: new Date() })
    .where(and(eq(cliDeviceGrant.id, grant.id), eq(cliDeviceGrant.status, "approved")))
    .returning();
  if (consumed.length === 0) return oauthError(c, "invalid_grant");

  try {
    return c.json(await mintAdminBotToken(approver, "cli-device"));
  } catch (e) {
    console.error("[/api/cli/token] signJWT failed:", e);
    return c.json({ error: "failed to mint token" }, 500);
  }
}

app.post("/api/cli/token", async (c) => {
  if (TEST_MODE) return c.json({ error: "cli device flow unavailable in test mode" }, 404);

  let body: Record<string, unknown>;
  try {
    body = await readJsonObject(c);
  } catch (e) {
    return c.json({ error: (e as Error).message }, 400);
  }

  const grantType = String(body.grant_type ?? (
    body.device_code ? "urn:ietf:params:oauth:grant-type:device_code" : "authorization_code"
  ));
  if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
    if (typeof body.device_code !== "string" || !body.device_code) {
      return oauthError(c, "invalid_request", 400, { error_description: "device_code is required" });
    }
    const grant = await findCliGrantByDeviceCode(body.device_code);
    if (!grant) return oauthError(c, "invalid_grant");
    return consumeApprovedCliGrant(c, grant);
  }

  if (grantType === "authorization_code") {
    if (typeof body.code !== "string" || !body.code) {
      return oauthError(c, "invalid_request", 400, { error_description: "code is required" });
    }
    const grant = await findCliGrantByExchangeCode(body.code);
    if (!grant) return oauthError(c, "invalid_grant");
    if (grant.codeChallenge && !verifyPkceS256(body.code_verifier, grant.codeChallenge)) {
      return oauthError(c, "invalid_grant", 400, { error_description: "PKCE verification failed" });
    }
    return consumeApprovedCliGrant(c, grant);
  }

  return oauthError(c, "unsupported_grant_type");
});

// ── User-token CLI flow (native desktop apps) ──────────────────────────────
//
// Companion to /api/cli/device above. The bot-token flow exists so an admin
// can approve an unattended request and hand a `role=admin, purpose=bot`
// JWT to a CLI/agent. This flow exists so the user signs in to the browser
// the normal way (Microsoft/Google), and a native desktop app on the same
// machine gets the user's own JWT delivered to a loopback listener.
//
// No approval ceremony — the user *is* the requester, so there's nothing
// to gate beyond the sign-in itself. No `where_happening`/`intended_use`
// metadata — that's a bot-mint concept; for a personal app it's noise.
//
// Flow (RFC 8252 — OAuth 2.0 for Native Apps):
//   1. Desktop opens listener at 127.0.0.1:<ephemeral>/callback
//   2. Desktop opens browser at /api/auth/cli/user-login with
//      redirect_uri, state, code_challenge, code_challenge_method=S256
//   3. If no session → bounce through /sign-in/microsoft, return here
//      after sign-in. If session → mint one-time code, redirect browser
//      to redirect_uri?code=...&state=...
//   4. Desktop POSTs to /api/auth/cli/user-token with code + code_verifier
//      + redirect_uri. JWT comes back in the POST response — never travels
//      through the browser, never lands in browser history.
//
// In-memory grant store. k8s/templates/deployment.yaml pins replicas: 1,
// so a single Map is the source of truth; a pod restart drops in-flight
// grants but the user just clicks sign-in again. 5-minute code TTL.

const USER_LOGIN_CODE_TTL_SECONDS = 5 * 60;
const USER_LOGIN_TOKEN_TTL_SECONDS = 24 * 60 * 60;

interface UserLoginGrant {
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  expiresAt: number;
}

const userLoginGrants = new Map<string, UserLoginGrant>();

function pruneExpiredUserLoginGrants(now = Date.now()) {
  for (const [k, g] of userLoginGrants) {
    if (g.expiresAt <= now) userLoginGrants.delete(k);
  }
}

// Better Auth's `asResponse: true` returns a full Response object including
// any Set-Cookie headers the call wants to set (e.g. the PKCE/state cookie
// for sign-in, the session-clear cookie for sign-out). We copy those across
// onto our own 302 so the browser has the cookies in hand before it follows
// the redirect. Without this, Microsoft's callback throws `state_mismatch`
// because the state cookie was never sent to the browser.
function copySetCookies(from: Response, to: Response): void {
  for (const cookie of from.headers.getSetCookie()) {
    to.headers.append("set-cookie", cookie);
  }
}

// Shared social sign-in entrypoint. POST is the form-driven path from
// this service's own dashboard. GET with a `callbackURL` query param is the
// cross-app sign-in path: downstream apps (e.g. tank.romaine.life) link
// here with their post-sign-in URL and the user gets redirected back to
// the app after the provider completes. Better Auth validates callbackURL
// against `trustedOrigins` in auth.ts — passing an unlisted origin throws.
async function socialSignInRedirect(c: Context, provider: "microsoft" | "google", callbackURL: string) {
  try {
    const authRes = await auth.api.signInSocial({
      body: { provider, callbackURL },
      headers: c.req.raw.headers,
      asResponse: true,
    });
    if (!authRes.ok) {
      console.error(`[sign-in:${provider}] better-auth returned`, authRes.status, await authRes.text());
      return c.text("sign-in failed", 500);
    }
    const data = await authRes.json() as { url?: string };
    if (!data.url) {
      console.error(`[sign-in:${provider}] better-auth response missing url`, data);
      return c.text("sign-in failed", 500);
    }
    const redirect = new Response(null, { status: 302, headers: { Location: data.url } });
    copySetCookies(authRes, redirect);
    return redirect;
  } catch (err) {
    console.error(`[sign-in:${provider}] threw:`, err);
    return c.text("sign-in failed", 500);
  }
}

function testSignIn(c: Context, callbackURL: string) {
  setTestCookie(c);
  return c.redirect(callbackURL);
}

async function trustedCallbackURL(callbackURL: string | undefined, fallback: string): Promise<string> {
  if (!callbackURL) return fallback;
  if (callbackURL.startsWith("/") && !callbackURL.startsWith("//")) return callbackURL;

  let parsed: URL;
  try {
    parsed = new URL(callbackURL);
  } catch {
    return fallback;
  }

  for (const pattern of await resolveAllTrustedOrigins()) {
    if (matchWildcard(pattern, parsed.origin)) return parsed.toString();
  }
  return fallback;
}

async function signOutCallbackURL(c: Context): Promise<string> {
  let callbackURL = c.req.query("callbackURL");
  try {
    const body = await c.req.parseBody();
    const fromBody = body.callbackURL;
    if (typeof fromBody === "string") callbackURL = fromBody;
  } catch {
    // Sign-out still works without a callback body.
  }
  return trustedCallbackURL(callbackURL, "/");
}

app.post("/sign-in/microsoft", (c) =>
  TEST_MODE ? testSignIn(c, "/") : socialSignInRedirect(c, "microsoft", "/"));
app.get("/sign-in/microsoft", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return TEST_MODE ? testSignIn(c, callbackURL) : socialSignInRedirect(c, "microsoft", callbackURL);
});
app.post("/sign-in/google", (c) =>
  TEST_MODE ? testSignIn(c, "/") : socialSignInRedirect(c, "google", "/"));
app.get("/sign-in/google", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return TEST_MODE ? testSignIn(c, callbackURL) : socialSignInRedirect(c, "google", callbackURL);
});

app.post("/sign-out", async (c) => {
  const callbackURL = await signOutCallbackURL(c);
  if (TEST_MODE) {
    clearTestCookie(c);
    return c.redirect(callbackURL);
  }
  try {
    const authRes = await auth.api.signOut({
      headers: c.req.raw.headers,
      asResponse: true,
    });
    const redirect = new Response(null, { status: 302, headers: { Location: callbackURL } });
    copySetCookies(authRes, redirect);
    return redirect;
  } catch (err) {
    console.error("[sign-out] threw:", err);
    return c.redirect(callbackURL);
  }
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`auth listening on :${info.port}`);
});
