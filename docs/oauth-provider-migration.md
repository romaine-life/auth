# Migrating to `@better-auth/oauth-provider`

**Status:** dependency groundwork landed; the plugin swap is designed and not yet written.
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

## What has landed

The dependency set only, and it is verified rather than assumed:

- `better-auth` 1.6.11 → 1.6.27, `jose` 5 → 6, `@better-auth/oauth-provider` 1.6.27 added.
- The jose major cost **one line**: v6 removed the `KeyLike` type alias, used once in
  `admin-bearer.test.ts`. Every jose API this service actually uses — `SignJWT`, `jwtVerify`,
  `generateKeyPair`, `exportJWK`, `createLocalJWKSet`, `createRemoteJWKSet` — is unchanged between
  v5 and v6. The removals in that major (`importJWK` oct handling, PBES2 opt-in, JWE `zip`) touch
  nothing here.
- `tsc --noEmit` clean; 159/159 unit tests pass.

## What the swap actually involves

Not a rename. The successor's model differs in three ways that each carry real risk.

### 1. Clients move from code into the database

Today four clients are declared statically in `src/auth.ts` under `trustedClients`. The successor
has no such option: clients are rows in a new `oauthClient` table, created through its
`createOAuthClient` server function, with `cachedTrustedClients?: Set<string>` naming which to hold
in memory.

Grafana's secret comes from `OIDC_GRAFANA_CLIENT_SECRET`, so the rows cannot be seeded by SQL. This
needs a **boot-time reconciliation** that upserts the four clients from environment configuration —
new code, and it must be idempotent because it runs on every pod start.

### 2. One claims hook becomes three, and getting it wrong is silent

`getAdditionalUserInfoClaim` currently feeds `role`, `groups` and `apps` into both the id_token and
the userinfo response. The successor splits this into `customIdTokenClaims`, `customUserInfoClaims`
and `customAccessTokenClaims`.

**This is the dangerous one.** Grafana reads `role` via `role_attribute_path`; Argo CD's RBAC
matches on `groups` (`scopes: '[groups]'` → `g, admin, role:admin`). If those claims stop being
emitted, nothing errors — Grafana quietly demotes every user to Viewer and Argo CD stops matching
any RBAC rule. Both hooks must be wired, and the resulting id_token inspected against a real login
before this is trusted.

### 3. Four new tables, three old ones retired

`oauthClient`, `oauthRefreshToken`, `oauthAccessToken`, `oauthConsent` — with foreign keys to
`user` and `session`, and several `string[]` columns whose Postgres representation must come from
better-auth's own generator (`npx @better-auth/cli generate`) rather than being hand-written. The
existing `oauth_application`, `oauth_access_token` and `oauth_consent` tables are retired after
cutover, not before: every live Grafana and Argo CD session is a row in the old ones.

## The per-client refresh lifetime, reconsidered

Decision 1 of the Chess Tactics audit assumed this migration would carry a per-client refresh
lifetime, so the game could hold 90-day sessions while Grafana and Argo CD kept 7 days.

**Neither package offers it.** `refreshTokenExpiresIn` is plugin-global in both (default now 30
days). Building it means reaching into vendor internals — `createRefreshToken` honours
`payload?.exp` if present, so it is possible, but a local extension around an authorization
server's token lifetimes is exactly the kind of code that should not be bespoke.

The simpler answer is that the knob is in the wrong place. **An authorization server sets a
maximum; each relying party sets its own session policy beneath it.** Grafana has
`login_maximum_lifetime_duration` and its own token rotation; Argo CD issues its own JWT with its
own expiry. Raising the shared refresh lifetime to 90 days does not by itself lengthen a Grafana or
Argo CD session — those are governed where they belong, in Grafana and Argo CD.

That removes the need for a custom extension entirely, and it is why the plugin authors do not
offer one. **This is a change from what decision 1 assumed and should be confirmed before rollout.**

## Ordering constraint

Fixing F5 without raising the refresh lifetime **shortens** Chess Tactics sessions rather than
lengthening them. Today the F5 bug re-stamps the expiry on every refresh, so an active session
renews indefinitely and the 7-day setting never bites. Correct rotation makes that 7-day wall real.

So the lifetime change and the F5 fix must land in the same rollout, or the first deploy regresses
the very sessions ADR-0576 was built to keep alive.

## Why this is not written yet

It cannot be verified from here. This repository's tests are `tsx --test src/*.test.ts` — unit
tests with no database — and there is no local Postgres. The pieces that would fail are exactly the
ones no unit test reaches: the schema mapping, the client seeding, and whether a real id_token
still carries `role` and `groups`.

A migration of the identity provider that has never completed a single real login, landing on the
service that gates Grafana and Argo CD, is not a thing to merge on a green typecheck. What it needs
is a disposable Postgres and one real end-to-end login per relying party — the same verification
the Chess Tactics side got from its smoke tests.
