-- OAuth 2.1 provider tables (@better-auth/oauth-provider), replacing the deprecated
-- better-auth/plugins `oidcProvider` surface created by drizzle/0001.
--
-- WHY: two defects in the old plugin, confirmed present in its own latest release and therefore
-- never going to be fixed there.
--
--   * Refresh rotation never invalidated the presented token. The old code created a new
--     oauth_access_token row and left the previous refresh token valid until its own expiry, so a
--     replayed token produced no conflict and rotation bought nothing (RFC 9700 §4.14.2). It also
--     re-stamped the expiry on every refresh, so an active chain never expired at all — which
--     draft-ietf-oauth-browser-based-apps-26 §6.3.2.3-4 forbids outright.
--   * `auth_time` was emitted in MILLISECONDS where OIDC Core §2 requires seconds, so any relying
--     party checking authentication freshness saw a time in the far future and passed
--     unconditionally.
--
-- The new `oauth_refresh_token.revoked` column is what fixes the first: rotation stamps the token
-- just presented, and presenting a stamped token revokes the whole family for that (client, user).
--
-- SHAPE: expand/contract. The two colliding legacy tables are RENAMED rather than dropped, so this
-- migration is reversible by renaming them back, and a rollback to the previous image finds its
-- data intact. drizzle/0003 drops them once the rollout is confirmed.
--
-- COST, stated plainly: every live Grafana, Argo CD and ambience session ends at cutover. The old
-- opaque tokens are meaningless to the new plugin — different columns, different issuance logic —
-- so there is nothing to carry across. Everyone signs in once more. This is the same cost Chess
-- Tactics accepted in its ADR-0576 and it is not avoidable by a cleverer migration.
--
-- Column names are snake_case to match every other table here; Better Auth reaches them through
-- the drizzle models in src/db/schema.ts, whose EXPORT names are what the plugin resolves. The
-- generator (scripts/emit-oauth-migration.mjs) emits quoted camelCase because it does not know
-- about that mapping; src/oauth-provider.integration.test.ts pins the two together.
--
-- Apply BEFORE rolling the auth Deployment to the image that loads the new plugin.
--
--   kubectl exec -n auth -i auth-db-1 -c postgres -- \
--     psql -U postgres -d auth < drizzle/0002-oauth-provider.sql
--
-- Idempotent on re-apply.

BEGIN;

-- Move the old plugin's tables aside. `oauth_application` keeps its name: nothing in the new
-- schema claims it, and leaving it in place makes the rollback obvious.
ALTER TABLE IF EXISTS "oauth_access_token" RENAME TO "oauth_access_token_legacy";
ALTER TABLE IF EXISTS "oauth_consent" RENAME TO "oauth_consent_legacy";

CREATE TABLE IF NOT EXISTS "oauth_client" (
  "id"                          text PRIMARY KEY NOT NULL,
  "client_id"                   text NOT NULL UNIQUE,
  "client_secret"               text,
  "disabled"                    boolean DEFAULT false,
  "skip_consent"                boolean,
  "enable_end_session"          boolean,
  "subject_type"                text,
  "scopes"                      jsonb,
  "user_id"                     text REFERENCES "user"("id") ON DELETE CASCADE,
  "created_at"                  timestamp DEFAULT now(),
  "updated_at"                  timestamp DEFAULT now(),
  "name"                        text,
  "uri"                         text,
  "icon"                        text,
  "contacts"                    jsonb,
  "tos"                         text,
  "policy"                      text,
  "software_id"                 text,
  "software_version"            text,
  "software_statement"          text,
  "redirect_uris"               jsonb NOT NULL,
  "post_logout_redirect_uris"   jsonb,
  "token_endpoint_auth_method"  text,
  "grant_types"                 jsonb,
  "response_types"              jsonb,
  "public"                      boolean,
  "type"                        text,
  "require_pkce"                boolean,
  "reference_id"                text,
  "metadata"                    jsonb
);

CREATE INDEX IF NOT EXISTS "oauth_client_user_id_idx" ON "oauth_client"("user_id");

CREATE TABLE IF NOT EXISTS "oauth_refresh_token" (
  "id"           text PRIMARY KEY NOT NULL,
  "token"        text NOT NULL UNIQUE,
  "client_id"    text NOT NULL REFERENCES "oauth_client"("client_id") ON DELETE CASCADE,
  "session_id"   text REFERENCES "session"("id") ON DELETE SET NULL,
  "user_id"      text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "reference_id" text,
  "expires_at"   timestamp NOT NULL,
  "created_at"   timestamp NOT NULL DEFAULT now(),
  -- The column this migration exists for. Non-null means the token was spent by a rotation;
  -- presenting it again is a replay and revokes the family.
  "revoked"      timestamp,
  "auth_time"    timestamp,
  "scopes"       jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS "oauth_refresh_token_client_id_idx" ON "oauth_refresh_token"("client_id");
CREATE INDEX IF NOT EXISTS "oauth_refresh_token_session_id_idx" ON "oauth_refresh_token"("session_id");
CREATE INDEX IF NOT EXISTS "oauth_refresh_token_user_id_idx" ON "oauth_refresh_token"("user_id");

CREATE TABLE IF NOT EXISTS "oauth_access_token" (
  "id"           text PRIMARY KEY NOT NULL,
  "token"        text NOT NULL UNIQUE,
  "client_id"    text NOT NULL REFERENCES "oauth_client"("client_id") ON DELETE CASCADE,
  "session_id"   text REFERENCES "session"("id") ON DELETE SET NULL,
  "user_id"      text REFERENCES "user"("id") ON DELETE CASCADE,
  "reference_id" text,
  "refresh_id"   text REFERENCES "oauth_refresh_token"("id") ON DELETE CASCADE,
  "expires_at"   timestamp NOT NULL,
  "created_at"   timestamp NOT NULL DEFAULT now(),
  "scopes"       jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS "oauth_access_token_client_id_idx" ON "oauth_access_token"("client_id");
CREATE INDEX IF NOT EXISTS "oauth_access_token_session_id_idx" ON "oauth_access_token"("session_id");
CREATE INDEX IF NOT EXISTS "oauth_access_token_user_id_idx" ON "oauth_access_token"("user_id");
CREATE INDEX IF NOT EXISTS "oauth_access_token_refresh_id_idx" ON "oauth_access_token"("refresh_id");

CREATE TABLE IF NOT EXISTS "oauth_consent" (
  "id"           text PRIMARY KEY NOT NULL,
  "client_id"    text NOT NULL REFERENCES "oauth_client"("client_id") ON DELETE CASCADE,
  "user_id"      text REFERENCES "user"("id") ON DELETE CASCADE,
  "reference_id" text,
  "scopes"       jsonb NOT NULL,
  "created_at"   timestamp NOT NULL DEFAULT now(),
  "updated_at"   timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "oauth_consent_client_id_idx" ON "oauth_consent"("client_id");
CREATE INDEX IF NOT EXISTS "oauth_consent_user_id_idx" ON "oauth_consent"("user_id");

-- The application connects as `auth`, and every pre-existing table in this database is OWNED by
-- that role rather than merely granted to it. Tables created by `psql -U postgres` are owned by
-- postgres, and the app then gets `permission denied` on its very first query — which is exactly
-- what happened on the first rollout of this migration, crash-looping the new pod until ownership
-- was corrected by hand. Setting it here makes the migration complete on its own terms.
ALTER TABLE "oauth_client" OWNER TO auth;
ALTER TABLE "oauth_refresh_token" OWNER TO auth;
ALTER TABLE "oauth_access_token" OWNER TO auth;
ALTER TABLE "oauth_consent" OWNER TO auth;

COMMIT;
