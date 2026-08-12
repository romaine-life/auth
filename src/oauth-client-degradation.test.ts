// Deployment-ordering safety, in its own file because it must run in its own PROCESS.
//
// @better-auth/oauth-provider caches trusted clients in a module-level Map that is never
// invalidated, so a client read once stays read for the life of the process regardless of which
// betterAuth() instance asked. That is fine in production — one process, one instance — and it is
// also why provisioning a secret requires a pod RESTART to take effect, not merely a redeploy of
// the secret. It means this case cannot share a process with the tests that register the same
// client confidential.

import assert from "node:assert/strict";
import test from "node:test";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { KyselyPGlite } from "kysely-pglite";
import { createHash, randomBytes } from "node:crypto";
import { OAUTH_CLIENT_IDS, hashClientSecret, reconcileOAuthClients } from "./oauth-clients.js";

const BASE_URL = "http://localhost:3000";

test("a missing client secret degrades that one client, it does not take the server down", async () => {
  // The failure mode this guards is a deploy ordering accident: the image ships before the Key
  // Vault secret exists. Aborting startup would be defensible for a single-tenant app and is
  // catastrophic here — this process is the authorization server for Grafana, Argo CD, ambience
  // and Chess Tactics, and the tools you would use to diagnose the outage are behind it.
  process.env.OIDC_GRAFANA_CLIENT_SECRET = "grafana-test-secret";
  delete process.env.OIDC_CHESS_TACTICS_CLIENT_SECRET;

  const { dialect, client } = await KyselyPGlite.create();
  const auth = betterAuth({
    baseURL: BASE_URL,
    secret: "integration-test-secret-not-a-real-one",
    database: { dialect, type: "postgres" },
    emailAndPassword: { enabled: true },
    user: {
      additionalFields: {
        role: { type: "string", defaultValue: "pending", input: false },
        apps: { type: "string", defaultValue: "{}", input: false },
      },
    },
    plugins: [
      jwt({ jwks: { keyPairConfig: { alg: "RS256" } } }),
      oauthProvider({
        loginPage: "/",
        consentPage: "/",
        storeClientSecret: { hash: async (secret: string) => hashClientSecret(secret) },
        storeTokens: "hashed",
        allowDynamicClientRegistration: false,
        scopes: ["openid", "email", "profile", "offline_access"],
        accessTokenExpiresIn: 3600,
        refreshTokenExpiresIn: 60 * 60 * 24 * 90,
        cachedTrustedClients: new Set(OAUTH_CLIENT_IDS),
      }),
    ],
  });
  const { runMigrations } = await getMigrations(
    (auth as unknown as { options: Record<string, unknown> }).options as never,
  );
  await runMigrations();

  // Startup must COMPLETE. This is the assertion — before the fix it threw here and the pod
  // would have crash-looped, taking sign-in away from every relying party.
  await reconcileOAuthClients(auth as never);

  const clients = await client.query<{ client_id: string; public: boolean }>(
    'SELECT "clientId" AS client_id, public FROM "oauthClient" ORDER BY "clientId"',
  );
  assert.equal(clients.rows.length, 4, "every other client must still be registered");
  const chess = clients.rows.find((row) => row.client_id === "chess-tactics");
  assert.equal(chess?.public, true, "the secretless client falls back to public rather than aborting");

  // And it still signs in — as a public client, which is exactly what it is today.
  const call = (path: string, init: RequestInit = {}) =>
    auth.handler(new Request(`${BASE_URL}/api/auth${path}`, init));
  const signUp = await call("/sign-up/email", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "owner@romaine.life", name: "Owner", password: "integration-test-password" }),
  });
  const cookie = (signUp.headers.getSetCookie?.() ?? []).map((c) => c.split(";", 1)[0]).join("; ");

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const query = new URLSearchParams({
    client_id: "chess-tactics",
    response_type: "code",
    redirect_uri: "https://chess-tactics.com/api/auth/callback",
    scope: "openid profile email offline_access",
    state: "s",
    nonce: "n",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const authorize = await call(`/oauth2/authorize?${query}`, { headers: { cookie } });
  const code = new URL(authorize.headers.get("location")!).searchParams.get("code")!;
  const token = await call("/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://chess-tactics.com/api/auth/callback",
      client_id: "chess-tactics",
      code_verifier: verifier,
    }).toString(),
  });
  assert.equal(token.status, 200, `degraded client must still sign in: ${await token.clone().text()}`);
});
