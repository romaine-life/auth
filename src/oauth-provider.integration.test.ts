// End-to-end verification of the OAuth provider against a real Postgres.
//
// PGlite is Postgres compiled to WASM — a genuine engine with genuine DDL and constraints, in
// process. It exists here because the parts of this migration that can fail are exactly the parts
// no unit test reaches: whether the generated schema actually applies, whether client
// reconciliation writes rows the plugin can read, and whether a real id_token still carries the
// claims Grafana and Argo CD authorize from.
//
// Losing those claims does not raise an error anywhere. Grafana quietly demotes every user to
// Viewer; Argo CD matches no RBAC rule. The only way to know is to complete a login and read the
// token, which is what this does.

import assert from "node:assert/strict";
import test from "node:test";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { KyselyPGlite } from "kysely-pglite";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { getTableColumns } from "drizzle-orm";
import * as schema from "./db/schema.js";
import { decodeJwt } from "jose";
import { OAUTH_CLIENT_IDS, hashClientSecret, reconcileOAuthClients } from "./oauth-clients.js";

// A bare origin, as in production. The previous value happened to make the issuer mismatch
// invisible; the relying parties are configured against the ORIGIN, not the mount path.
const BASE_URL = "https://auth.example.test";

function platformClaims(user: Record<string, unknown>): Record<string, unknown> {
  let apps: Record<string, unknown> = {};
  try {
    apps = JSON.parse(typeof user.apps === "string" ? user.apps : "{}");
  } catch { /* mirrors src/auth.ts */ }
  const role = typeof user.role === "string" ? user.role : "user";
  return { role, groups: [role], apps };
}

/**
 * Boot a provider over a fresh in-process Postgres.
 *
 * The schema comes from Better Auth's own `getMigrations`, not from hand-written DDL — the same
 * source the production migration must be generated from, so a mismatch between what the plugin
 * expects and what the tables provide fails here rather than in front of Grafana.
 */
async function bootProvider({ withChessTacticsSecret = true } = {}) {
  const { dialect, client } = await KyselyPGlite.create();
  process.env.OIDC_GRAFANA_CLIENT_SECRET = "grafana-test-secret";
  if (withChessTacticsSecret) process.env.OIDC_CHESS_TACTICS_CLIENT_SECRET = "chess-tactics-test-secret";
  else delete process.env.OIDC_CHESS_TACTICS_CLIENT_SECRET;

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
      jwt({ jwks: { keyPairConfig: { alg: "RS256" } }, jwt: { issuer: BASE_URL } }),
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
        customIdTokenClaims: ({ user }) => platformClaims(user as Record<string, unknown>),
        customUserInfoClaims: ({ user }) => platformClaims(user as Record<string, unknown>),
      }),
    ],
  });

  const { runMigrations, compileMigrations } = await getMigrations(
    (auth as unknown as { options: Record<string, unknown> }).options as never,
  );
  await runMigrations();
  await reconcileOAuthClients(auth as never);

  /**
   * Call the provider over HTTP.
   *
   * Not `auth.api.*`: the plugin requires a real `Request` on the context and answers
   * `request not found` without one. Going through the handler is also what a relying party
   * does, so state binding, PKCE and client authentication are all exercised for real.
   */
  const call = (path: string, init: RequestInit = {}) =>
    auth.handler(new Request(`${BASE_URL}/api/auth${path}`, init));

  return { auth, client, compileMigrations, call };
}

type Harness = Awaited<ReturnType<typeof bootProvider>>;

/** Complete an authorization-code request and return the code it issued. */
async function authorizeCode(
  harness: Harness,
  cookie: string,
  {
    scope = "openid profile email offline_access",
    clientId = "chess-tactics",
    redirectUri = "https://chess-tactics.com/api/auth/callback",
  } = {},
) {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const query = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    scope,
    state: "state-value",
    nonce: "nonce-value",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const response = await harness.call(`/oauth2/authorize?${query}`, { headers: { cookie } });
  const location = response.headers.get("location");
  assert.ok(location, `authorize must redirect, got ${response.status}: ${await response.clone().text()}`);
  const code = new URL(location).searchParams.get("code");
  assert.ok(code, `authorize must return a code, got ${location}`);
  return { code, verifier };
}

/** Exchange at the token endpoint with form encoding, as a relying party would. */
function tokenRequest(harness: Harness, form: Record<string, string>) {
  return harness.call("/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
}

/** Sign up a user and return their session token plus a cookie header carrying it. */
async function signUpUser(harness: Harness) {
  const response = await harness.call("/sign-up/email", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "owner@romaine.life", name: "Owner", password: "integration-test-password" }),
  });
  const cookie = (response.headers.getSetCookie?.() ?? [])
    .map((value) => value.split(";", 1)[0])
    .join("; ");
  assert.ok(cookie, "sign-up must establish a session cookie");
  return cookie;
}

test("the generated schema applies and the declared clients reconcile into it", async () => {
  const { client } = await bootProvider();
  const tables = await client.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' ORDER BY table_name`,
  );
  const names = tables.rows.map((row) => row.table_name);
  // Better Auth names tables after the MODEL when it generates them directly, as here. In
  // production the drizzle adapter maps each model to the snake_case table declared in
  // src/db/schema.ts, which is why that file must gain all four — see the schema-parity test
  // below. This asserts the plugin's own model set, not the physical names production uses.
  for (const required of ["oauthClient", "oauthRefreshToken", "oauthAccessToken", "oauthConsent"]) {
    assert.ok(names.includes(required), `missing model ${required} — have: ${names.join(", ")}`);
  }

  const clients = await client.query<{ client_id: string; public: boolean }>(
    'SELECT "clientId" AS client_id, public FROM "oauthClient" ORDER BY "clientId"',
  );
  assert.deepEqual(
    clients.rows.map((row) => row.client_id),
    ["ambience", "argocd", "chess-tactics", "grafana"],
  );
  // Grafana is confidential outright: it has always held a secret.
  const grafana = clients.rows.find((row) => row.client_id === "grafana");
  assert.equal(grafana?.public, false, "grafana must be registered confidential");

  // Chess Tactics is mid-promotion (ADR-0576 makes it confidential; `enforceConfidential: false`
  // keeps it accepting both while the relying party catches up). Public WITH a secret on file is
  // that state, and it is the only one that survives the switchover.
  const chess = clients.rows.find((row) => row.client_id === "chess-tactics");
  assert.equal(chess?.public, true, "chess-tactics stays public until the promotion is enforced");
  const chessSecret = await client.query<{ has_secret: boolean }>(
    `SELECT ("clientSecret" IS NOT NULL) AS has_secret FROM "oauthClient" WHERE "clientId" = 'chess-tactics'`,
  );
  assert.equal(chessSecret.rows[0].has_secret, true, "with its secret already on file");
});

test("reconciliation is idempotent and never orphans a client row", async () => {
  const { auth, client } = await bootProvider();
  const before = await client.query<{ id: string }>('SELECT id FROM "oauthClient" ORDER BY "clientId"');
  // A second pod start, or a redeploy.
  await reconcileOAuthClients(auth as never);
  await reconcileOAuthClients(auth as never);
  const after = await client.query<{ id: string }>('SELECT id FROM "oauthClient" ORDER BY "clientId"');
  assert.equal(after.rows.length, 4, "reconciliation must not duplicate clients");
  assert.deepEqual(
    after.rows.map((row) => row.id),
    before.rows.map((row) => row.id),
    "client ids must survive: live refresh tokens and consents reference them",
  );
});

test("a real login yields an id_token carrying role, groups and apps", async () => {
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);
  // The claim Grafana authorizes from. Set it to something distinguishable from the default.
  await harness.client.query("UPDATE \"user\" SET role = 'admin', apps = '{\"chess\":{\"beta\":true}}'");

  const { code, verifier } = await authorizeCode(harness, cookie);
  const token = await tokenRequest(harness, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://chess-tactics.com/api/auth/callback",
    client_id: "chess-tactics",
    client_secret: "chess-tactics-test-secret",
    code_verifier: verifier,
  });
  assert.equal(token.status, 200, `token exchange failed: ${await token.clone().text()}`);
  const tokens = await token.json() as { id_token?: string; refresh_token?: string; access_token: string };

  assert.ok(tokens.id_token, "an openid request must return an id_token");
  const claims = decodeJwt(tokens.id_token);

  // THE assertion this whole file exists for. Both claims are read by ANOTHER system's
  // authorization, and losing either fails silently rather than loudly.
  assert.equal(claims.role, "admin", "Grafana reads `role` through role_attribute_path");
  assert.deepEqual(claims.groups, ["admin"], "Argo CD matches RBAC on `groups`");
  assert.deepEqual(claims.apps, { chess: { beta: true } }, "apps must be an object, not a JSON string");

  // F11: OIDC Core §2 requires auth_time in SECONDS. The old plugin emitted milliseconds, which
  // reads as a time ~50,000 years hence and makes any freshness check pass unconditionally.
  const authTime = Number(claims.auth_time);
  assert.ok(Number.isFinite(authTime), "auth_time must be present");
  const skew = Math.abs(authTime - Math.floor(Date.now() / 1000));
  assert.ok(skew < 300, `auth_time must be seconds, got ${authTime} (skew ${skew}s)`);

  assert.ok(tokens.refresh_token, "offline_access must yield a refresh token");

  // The claim that took production down. Left to its default, Better Auth issues `iss` as its
  // MOUNT path (`<origin>/api/auth`), while every relying party — and the root discovery document
  // — is configured against the bare origin, so each one rejects the token. Chess Tactics failed
  // every callback with `oidc_id_token_invalid`; Argo CD enforces the same match.
  assert.equal(claims.iss, BASE_URL, "the id_token issuer must be the origin relying parties expect");

  // The same claims must appear at userinfo. They were one hook before this migration and are
  // two now; letting them drift is how a relying party authorizes differently by surface.
  const userinfo = await harness.call("/oauth2/userinfo", {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(userinfo.status, 200, `userinfo failed: ${await userinfo.clone().text()}`);
  const info = await userinfo.json() as Record<string, unknown>;
  assert.equal(info.role, "admin", "userinfo must carry the same role as the id_token");
  assert.deepEqual(info.groups, ["admin"], "userinfo must carry the same groups as the id_token");
});

test("rotation invalidates the presented refresh token, and replay revokes the family", async () => {
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);
  const { code, verifier } = await authorizeCode(harness, cookie);
  const first = await (await tokenRequest(harness, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://chess-tactics.com/api/auth/callback",
    client_id: "chess-tactics",
    client_secret: "chess-tactics-test-secret",
    code_verifier: verifier,
  })).json() as { refresh_token: string };

  const refresh = (refresh_token: string) => tokenRequest(harness, {
    grant_type: "refresh_token",
    refresh_token,
    client_id: "chess-tactics",
    client_secret: "chess-tactics-test-secret",
  });

  const rotated = await refresh(first.refresh_token);
  assert.equal(rotated.status, 200, `refresh failed: ${await rotated.clone().text()}`);
  const second = await rotated.json() as { refresh_token: string };
  assert.notEqual(second.refresh_token, first.refresh_token, "rotation must issue a new token");

  // F5. Against the old plugin this replay SUCCEEDED, because the previous token was never
  // invalidated — rotation without invalidation buys nothing (RFC 9700 §4.14.2).
  const replay = await refresh(first.refresh_token);
  assert.ok(replay.status >= 400, "a rotated refresh token must be invalidated, not left live");

  // And the replay is treated as a breach: the family goes, including the token the legitimate
  // holder now carries. The server cannot tell victim from thief, so it ends both.
  const afterBreach = await refresh(second.refresh_token);
  assert.ok(afterBreach.status >= 400, "replaying a revoked token must revoke the whole family");

  const live = await harness.client.query<{ count: string }>(
    'SELECT count(*)::text AS count FROM "oauthRefreshToken" WHERE revoked IS NULL',
  );
  assert.equal(live.rows[0].count, "0", "no live refresh token may survive family revocation");
});

test("a confidential client must authenticate itself at the token endpoint", async () => {
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);
  // Grafana, because it is ENFORCED confidential. Chess Tactics is mid-promotion and deliberately
  // accepts both right now; asserting this against it would pass for the wrong reason once the
  // promotion completes and fail for the wrong reason before then.
  const { code, verifier } = await authorizeCode(harness, cookie, {
    clientId: "grafana",
    redirectUri: "https://grafana.romaine.life/login/generic_oauth",
    scope: "openid profile email",
  });

  const bare = await tokenRequest(harness, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://grafana.romaine.life/login/generic_oauth",
    client_id: "grafana",
    code_verifier: verifier,
  });
  assert.ok(bare.status >= 400, `a confidential client must authenticate: got ${bare.status}`);

  // And succeeds with it, so the failure above is about the secret and not the request shape.
  const { code: second, verifier: secondVerifier } = await authorizeCode(harness, cookie, {
    clientId: "grafana",
    redirectUri: "https://grafana.romaine.life/login/generic_oauth",
    scope: "openid profile email",
  });
  const authenticated = await tokenRequest(harness, {
    grant_type: "authorization_code",
    code: second,
    redirect_uri: "https://grafana.romaine.life/login/generic_oauth",
    client_id: "grafana",
    client_secret: "grafana-test-secret",
    code_verifier: secondVerifier,
  });
  assert.equal(authenticated.status, 200, await authenticated.clone().text());
});

test("an authorization code is redeemable exactly once", async () => {
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);
  const { code, verifier } = await authorizeCode(harness, cookie);
  const body = {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://chess-tactics.com/api/auth/callback",
    client_id: "chess-tactics",
    client_secret: "chess-tactics-test-secret",
    code_verifier: verifier,
  };
  assert.equal((await tokenRequest(harness, body)).status, 200);
  assert.ok((await tokenRequest(harness, body)).status >= 400, "a code must not be redeemable twice");
});

test("a mismatched PKCE verifier is refused", async () => {
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);
  const { code } = await authorizeCode(harness, cookie);
  const wrong = await tokenRequest(harness, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://chess-tactics.com/api/auth/callback",
    client_id: "chess-tactics",
    client_secret: "chess-tactics-test-secret",
    code_verifier: randomBytes(32).toString("base64url"),
  });
  assert.ok(wrong.status >= 400, "PKCE must bind the code to the request that started it");
});

test("the shipped migration produces exactly the tables the drizzle models map to", async () => {
  // The gap this closes is real and was found by the test above failing: Better Auth's generator
  // emits quoted camelCase table names, while every table in this database is snake_case and the
  // drizzle models are what bridge them. Nothing else compares the two, so a column renamed in
  // one and not the other would surface as a runtime error in front of Grafana.
  const { client } = await KyselyPGlite.create();
  const sql = readFileSync(new URL("../drizzle/0002-oauth-provider.sql", import.meta.url), "utf8");

  // Stand up what the migration expects to find in production: the `user` and `session` tables
  // its foreign keys reference, and the `auth` role it transfers ownership to. That role is not
  // incidental — the application connects as it, every existing table is owned by it, and the
  // first rollout of this migration crash-looped precisely because tables created by `postgres`
  // were not.
  await client.exec(`
    CREATE ROLE auth;
    CREATE TABLE "user" ("id" text PRIMARY KEY);
    CREATE TABLE "session" ("id" text PRIMARY KEY);
  `);
  await client.exec(sql);
  // Idempotent on re-apply, as the header claims.
  await client.exec(sql);

  const columns = await client.query<{ table_name: string; column_name: string }>(
    `SELECT table_name, column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name LIKE 'oauth%'
      ORDER BY table_name, column_name`,
  );
  const byTable = new Map<string, string[]>();
  for (const row of columns.rows) {
    byTable.set(row.table_name, [...(byTable.get(row.table_name) ?? []), row.column_name]);
  }

  for (const [model, table] of Object.entries({
    oauthClient: "oauth_client",
    oauthRefreshToken: "oauth_refresh_token",
    oauthAccessToken: "oauth_access_token",
    oauthConsent: "oauth_consent",
  })) {
    const actual = byTable.get(table);
    assert.ok(actual, `${model} maps to ${table}, which the migration did not create`);
    const declared = Object.values(getTableColumns(schema[model as keyof typeof schema] as never))
      .map((column) => (column as { name: string }).name)
      .sort();
    assert.deepEqual(
      actual.sort(),
      declared,
      `${table} columns must match the ${model} drizzle model exactly`,
    );
  }

  // Ownership transfers to the application's role, or the app gets `permission denied` on its
  // first query and the pod never becomes ready.
  const owners = await client.query<{ tablename: string; tableowner: string }>(
    "SELECT tablename, tableowner FROM pg_tables WHERE tablename LIKE 'oauth%' ORDER BY tablename",
  );
  for (const row of owners.rows) {
    assert.equal(row.tableowner, "auth", `${row.tablename} must be owned by the app role`);
  }

  // Expand/contract: the colliding legacy tables are moved aside, never dropped here.
  assert.match(sql, /RENAME TO "oauth_access_token_legacy"/);
  assert.match(sql, /RENAME TO "oauth_consent_legacy"/);
  assert.ok(!/DROP TABLE/i.test(sql), "0002 must not drop anything — rollback depends on it");
});

test("a client mid-promotion accepts a request with the secret and one without", async () => {
  // Promoting public -> confidential has no safe order on its own: the provider refuses a
  // confidential client that sends no secret, and refuses a secret from a client with none
  // registered. Flip either side first and every login of that client breaks until the other
  // catches up. Public-with-a-secret-on-file is the state that accepts both, and this proves it
  // — because the whole three-deploy promotion rests on it being true.
  const harness = await bootProvider();
  const cookie = await signUpUser(harness);

  const redeem = async (extra: Record<string, string>) => {
    const { code, verifier } = await authorizeCode(harness, cookie);
    return tokenRequest(harness, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://chess-tactics.com/api/auth/callback",
      client_id: "chess-tactics",
      code_verifier: verifier,
      ...extra,
    });
  };

  const withSecret = await redeem({ client_secret: "chess-tactics-test-secret" });
  assert.equal(withSecret.status, 200, `secret must be accepted: ${await withSecret.clone().text()}`);

  const withoutSecret = await redeem({});
  assert.equal(
    withoutSecret.status,
    200,
    `and a relying party that has not been given it yet must still work: ${await withoutSecret.clone().text()}`,
  );
});
