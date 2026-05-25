#!/usr/bin/env node
// Deterministic auditor for the auth.romaine.life → Grafana OIDC + bearer
// integration. Run after deploying the auth changes that add the OIDC
// provider plugin, and again after the Grafana side flips to using it.
//
// Usage:
//   node scripts/verify-grafana-oidc.mjs
//
// Optional env:
//   AUTH_BASE_URL    default https://auth.romaine.life
//   GRAFANA_BASE_URL default https://grafana.romaine.life
//   GRAFANA_BEARER   if set, also runs the bearer-auth check against
//                    Grafana's /api/user using this JWT (mint via the
//                    auth.romaine.life admin console → bot-tokens card,
//                    or via /admin/bot-tokens with an admin session).
//
// Exits 0 if every required check passes, 1 if any required check fails.
// The bearer check is skipped (not failed) when GRAFANA_BEARER is unset.

import { importJWK, jwtVerify } from "jose";

const AUTH_BASE = (process.env.AUTH_BASE_URL ?? "https://auth.romaine.life").replace(/\/$/, "");
const GRAFANA_BASE = (process.env.GRAFANA_BASE_URL ?? "https://grafana.romaine.life").replace(/\/$/, "");
const BEARER = process.env.GRAFANA_BEARER ?? "";

const results = [];
const record = (name, ok, detail) => {
  results.push({ name, ok, detail });
  const tag = ok ? "PASS" : "FAIL";
  console.log(`[${tag}] ${name}${detail ? ` — ${detail}` : ""}`);
};

// ── 1. OIDC discovery document ────────────────────────────────────────────
// The plugin mounts under /api/auth/*, so the discovery doc is at
// /api/auth/.well-known/openid-configuration. RPs configure the endpoints
// explicitly (Grafana doesn't autodiscover), but the doc is the canonical
// source of truth for the values they're configured against.
let discovery;
try {
  const url = `${AUTH_BASE}/api/auth/.well-known/openid-configuration`;
  const r = await fetch(url);
  if (!r.ok) {
    record("discovery doc reachable", false, `${url} → HTTP ${r.status}`);
  } else {
    discovery = await r.json();
    record("discovery doc reachable", true, url);
    const expectKeys = [
      "issuer",
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
    ];
    const missing = expectKeys.filter((k) => !discovery[k]);
    record(
      "discovery doc has required endpoints",
      missing.length === 0,
      missing.length === 0 ? expectKeys.join(", ") : `missing: ${missing.join(", ")}`,
    );
    // The id_token signing alg must include RS256 — otherwise useJWTPlugin
    // wiring didn't take and id_tokens won't verify against /api/auth/jwks.
    const algs = discovery.id_token_signing_alg_values_supported ?? [];
    record(
      "RS256 advertised for id_token signing",
      Array.isArray(algs) && algs.includes("RS256"),
      `advertised: ${JSON.stringify(algs)}`,
    );
  }
} catch (e) {
  record("discovery doc reachable", false, e.message);
}

// ── 2. JWKS ────────────────────────────────────────────────────────────────
// Same JWKS that the rest of romaine.life apps verify against. The OIDC
// id_token must be signed by one of these keys — that's the whole point of
// useJWTPlugin: true in the plugin config.
let jwks;
try {
  const url = discovery?.jwks_uri ?? `${AUTH_BASE}/api/auth/jwks`;
  const r = await fetch(url);
  if (!r.ok) {
    record("JWKS reachable", false, `${url} → HTTP ${r.status}`);
  } else {
    jwks = await r.json();
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    record(
      "JWKS reachable and non-empty",
      keys.length > 0,
      keys.length > 0 ? `${keys.length} key(s), first kid=${keys[0]?.kid}` : "no keys returned",
    );
    record(
      "JWKS contains an RS256 signing key",
      keys.some((k) => k.alg === "RS256" && k.use !== "enc"),
      keys.map((k) => `${k.kid}(${k.alg})`).join(", "),
    );
  }
} catch (e) {
  record("JWKS reachable", false, e.message);
}

// ── 3. /oauth2/authorize accepts our client_id ─────────────────────────────
// Probe with the Grafana client_id and a syntactically valid set of
// parameters. We expect either a 302 to /api/auth/sign-in (no session) or
// a 302 back to the redirect_uri (session present). What we MUST NOT see
// is a 4xx response body containing "unknown_client" or "invalid_client" —
// that means trustedClients didn't register Grafana correctly.
try {
  const authzUrl = new URL(discovery?.authorization_endpoint ?? `${AUTH_BASE}/api/auth/oauth2/authorize`);
  authzUrl.searchParams.set("response_type", "code");
  authzUrl.searchParams.set("client_id", "grafana");
  authzUrl.searchParams.set("redirect_uri", "https://grafana.romaine.life/login/generic_oauth");
  authzUrl.searchParams.set("scope", "openid email profile");
  authzUrl.searchParams.set("state", "verify-script-" + Date.now());
  // Synthetic PKCE — the plugin requires it. SHA256(verifier) base64url.
  // The verifier itself is "verify-script-pkce-verifier" (43-128 chars).
  // The challenge below is its actual S256 hash.
  authzUrl.searchParams.set(
    "code_challenge",
    "rrcaaA3CB0cF13r0X4F7uXC4ahL1qhU4j2j8AAd4gmU",
  );
  authzUrl.searchParams.set("code_challenge_method", "S256");

  const r = await fetch(authzUrl, { redirect: "manual" });
  // 302/303: success path (either bounce to login or to Grafana's callback).
  // 400 with body mentioning the client_id by name is the failure signal —
  // means the trustedClients lookup didn't match.
  if (r.status >= 300 && r.status < 400) {
    record(
      "/oauth2/authorize accepts client_id=grafana",
      true,
      `HTTP ${r.status} → ${r.headers.get("location")?.slice(0, 80) ?? "(no Location)"}`,
    );
  } else {
    const body = await r.text();
    const looksLikeUnknownClient = /unknown_client|invalid_client|client.*not.*found/i.test(body);
    record(
      "/oauth2/authorize accepts client_id=grafana",
      !looksLikeUnknownClient && r.status < 500,
      `HTTP ${r.status}, body[0..200]=${body.slice(0, 200).replace(/\s+/g, " ")}`,
    );
  }
} catch (e) {
  record("/oauth2/authorize reachable", false, e.message);
}

// ── 4. Bearer-auth path against Grafana ────────────────────────────────────
// Only runs if GRAFANA_BEARER is provided. Hits /api/user (returns the
// currently authenticated user's profile) and checks Grafana didn't
// 401/403. A 200 with a body containing the email claim is the success
// signal — Grafana verified the JWT against the same JWKS we just checked,
// pulled the email claim, and resolved a Grafana user.
if (BEARER) {
  // Sanity-check the JWT against the same JWKS first so we know if a
  // Grafana 4xx is a Grafana config issue versus a token issue.
  try {
    if (jwks) {
      const candidate = jwks.keys.find((k) => k.alg === "RS256" && k.use !== "enc") ?? jwks.keys[0];
      const key = await importJWK(candidate, "RS256");
      const { payload } = await jwtVerify(BEARER, key, {
        issuer: discovery?.issuer ?? AUTH_BASE,
      });
      record(
        "GRAFANA_BEARER verifies against JWKS locally",
        true,
        `sub=${payload.sub} email=${payload.email} role=${payload.role}`,
      );
    }
  } catch (e) {
    record(
      "GRAFANA_BEARER verifies against JWKS locally",
      false,
      e.message,
    );
  }

  // Try both header shapes since Grafana's auth.jwt accepts a custom
  // header (X-JWT-Assertion) on older versions and Authorization: Bearer
  // on 10.4+. The chart-pinned Grafana version drives which one the
  // values.yaml uses — we verify whichever works.
  for (const header of [
    { name: "Authorization", value: `Bearer ${BEARER}` },
    { name: "X-JWT-Assertion", value: BEARER },
  ]) {
    try {
      const r = await fetch(`${GRAFANA_BASE}/api/user`, {
        headers: { [header.name]: header.value },
      });
      const body = await r.text();
      const ok = r.status === 200 && /"email"/.test(body);
      record(
        `Grafana /api/user accepts JWT via ${header.name}`,
        ok,
        `HTTP ${r.status}${ok ? "" : `, body[0..160]=${body.slice(0, 160).replace(/\s+/g, " ")}`}`,
      );
      if (ok) break; // either header succeeding is enough
    } catch (e) {
      record(`Grafana /api/user accepts JWT via ${header.name}`, false, e.message);
    }
  }
} else {
  console.log("[SKIP] Grafana bearer-auth check — GRAFANA_BEARER not set");
}

// ── Summary ────────────────────────────────────────────────────────────────
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length > 0) {
  console.log("Failed:");
  for (const r of failed) console.log(`  - ${r.name}: ${r.detail ?? ""}`);
  process.exit(1);
}
