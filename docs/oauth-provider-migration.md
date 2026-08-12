# Migrating to `@better-auth/oauth-provider`

**Status:** implemented and verified end to end against a real Postgres. Not yet rolled out.
**Why it matters:** this repository is the authorization server for Grafana, Argo CD, ambience and
Chess Tactics. Getting it wrong takes out the tools you would use to diagnose it.

## What this is for

Two normative defects in the current `oidcProvider` plugin, confirmed present in its own latest
release (1.6.27) and therefore never going to be fixed there:

- **F5 — rotation without invalidation.** `index.mjs:465-487` creates a new `oauth_access_token`
  row on refresh and never invalidates the old refresh token, which stays valid until its own
  expiry. RFC 9700 §4.14.2 requires the previous token be invalidated; without that there is no
  conflict when a stolen token is replayed, so rotation provides none of its security value. It
  also re-stamps `refreshTokenExpiresAt` to now+7d on every refresh, so an active chain never
  expires — which draft-ietf-oauth-browser-based-apps-26 §6.3.2.3-4 forbids outright.
- **F11 — `auth_time` in the wrong unit.** `index.mjs:607` emits
  `new Date(session.createdAt).getTime()` — milliseconds, where OIDC Core §2 requires seconds. A
  relying party verifying authentication freshness computes a time in the far future, so a naive
  `now - auth_time <= max_age` check passes unconditionally.

Both are fixed in `@better-auth/oauth-provider@1.6.27`: refresh tokens carry a `revoked` column,
presenting a revoked token calls `invalidateRefreshFamily`, rotation preserves the original `exp`
rather than extending it, and `auth_time` is emitted in seconds.

## What landed

**The dependency set.** `better-auth` 1.6.11 → 1.6.27, `jose` 5 → 6,
`@better-auth/oauth-provider` 1.6.27. The jose major — feared to be the expensive part — cost
exactly one line: v6 removed the `KeyLike` type alias, used once in a test. Every API this service
uses (`SignJWT`, `jwtVerify`, `generateKeyPair`, `exportJWK`, `createLocalJWKSet`,
`createRemoteJWKSet`) is unchanged, and the removals in that major touch nothing here.

**The plugin swap**, in `src/auth.ts`. Three differences from the old plugin mattered:

1. **Clients are data, not config.** The successor has no `trustedClients`; clients are rows.
   `src/oauth-clients.ts` declares the four in code and reconciles them into `oauth_client` at
   boot, idempotently, awaited before `serve()` so no authorize call can arrive for a client that
   has not been written. A confidential client whose secret is missing throws and the process
   exits — registering it without one would silently downgrade it to something anybody could
   impersonate.
2. **One claims hook became three.** `customIdTokenClaims` and `customUserInfoClaims` are both
   wired to the same `platformClaims`, because they were one hook before and letting them drift is
   how a relying party ends up authorizing differently depending on which surface it read.
3. **We own the client-secret hash.** `storeClientSecret: { hash }` rather than `"hashed"`, so
   boot-time seeding can write a client without going through the plugin's registration endpoints.
   Unsalted SHA-256 is right for a machine-generated 256-bit secret and would be wrong for a
   password; the reasoning is in `src/oauth-clients.ts`.

**The migration**, `drizzle/0002-oauth-provider.sql`. Expand/contract: the two colliding legacy
tables are renamed aside rather than dropped, so a rollback finds its data intact. Generated from
Better Auth's own `compileMigrations` via `npm run oauth:emit-migration`, then written snake_case
to match every other table here — the generator emits quoted camelCase because it knows nothing of
the drizzle model mapping, and that gap is exactly what the parity test pins.

## How it was verified

`npm run test:oauth` boots the provider over **PGlite** — Postgres compiled to WASM, a real engine
with real DDL and real constraints — applies the generated schema, and drives the whole flow
through `auth.handler` with real `Request` objects. Eight tests, all passing:

- the schema applies and the four declared clients reconcile into it, with chess-tactics
  confidential;
- reconciliation is idempotent and preserves client row ids across restarts, because live refresh
  tokens reference them;
- **a real login yields an id_token carrying `role`, `groups` and `apps`** — the assertion the
  whole file exists for, since losing those silently demotes every Grafana user to Viewer and stops
  Argo CD matching any RBAC rule — and userinfo carries the same values;
- **`auth_time` is in seconds** (F11), asserted by skew against the wall clock rather than by
  reading the source;
- **rotation invalidates the presented refresh token, and replaying it revokes the whole family**
  (F5), with a database check that no live token survives;
- a confidential client cannot redeem a code without its secret;
- an authorization code is redeemable exactly once;
- a mismatched PKCE verifier is refused;
- the shipped migration produces exactly the columns the drizzle models map to.

Two of those found real defects while being written: the camelCase/snake_case table mismatch, and
a client secret written raw where the plugin expected it hashed. Neither would have failed a
typecheck.

## What rollout still requires

Verification here is not deployment. Before this ships:

1. **`OIDC_CHESS_TACTICS_CLIENT_SECRET` must exist in Key Vault** and be mounted into both this
   service and the Chess Tactics deployment. Chess Tactics becomes a confidential client
   (ADR-0576); until the secret is installed it falls back to sending only its client id.
2. **Apply `drizzle/0002` before rolling the image**, as with 0001.
3. **Every live Grafana, Argo CD and ambience session ends at cutover.** The old opaque tokens are
   meaningless to the new plugin, so there is nothing to carry across. Everyone signs in once more.
4. **Watch the first real Grafana login.** The claims are proven in the integration test, but
   Grafana's `role_attribute_path` and Argo CD's RBAC are configured in those systems, not here.
   One login each is the confirmation.
5. **`drizzle/0003` drops the `*_legacy` tables** once the rollout is confirmed. Not before.

## The per-client refresh lifetime, reconsidered

Decision 1 of the Chess Tactics audit assumed this migration would carry a per-client refresh
lifetime, so the game could hold 90-day sessions while Grafana and Argo CD kept 7 days.

**Neither package offers it.** `refreshTokenExpiresIn` is plugin-global in both.

The knob was in the wrong place. **An authorization server sets a maximum; each relying party sets
its own session policy beneath it.** Grafana has `login_maximum_lifetime_duration` and its own
token rotation; Argo CD issues its own JWT with its own expiry. Raising the shared refresh lifetime
to 90 days does not by itself lengthen a Grafana or Argo CD session. That removes the need for a
bespoke extension to an authorization server's token lifetimes, which is code that should not be
bespoke — and it is why the plugin authors do not offer one.

`refreshTokenExpiresIn` is therefore set to 90 days here, as the ceiling.

## Ordering constraint

Fixing F5 without raising the lifetime **shortens** Chess Tactics sessions rather than lengthening
them. Today's rotation bug re-stamps the expiry on every refresh, so an active chain renews
indefinitely and the old 7-day setting never bites; correct rotation makes that wall real. Both
changes are in this branch for exactly that reason — they must land together.
