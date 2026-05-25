-- OIDC provider plugin tables (better-auth/plugins/oidc-provider).
--
-- Created when src/auth.ts started loading the `oidcProvider` plugin to
-- give off-the-shelf relying parties (Grafana, future Argo CD UI) a
-- standard OAuth2/OIDC authorization-server surface. First-party
-- romaine.life apps that use the shared session cookie + JWKS continue
-- to ignore these tables.
--
-- Apply BEFORE rolling the auth Deployment to the image that loads the
-- plugin — the plugin queries oauth_application during /oauth2/authorize
-- on every RP login. Without these tables the endpoint 500s and the RP
-- flow breaks. The first-party cookie/JWKS path is unaffected either way.
--
-- One-shot apply against the auth-db CNPG cluster:
--
--   kubectl exec -n auth -i auth-db-1 -c postgres -- \
--     psql -U postgres -d auth < drizzle/0001-oidc-provider.sql
--
-- Idempotent on re-apply (IF NOT EXISTS on every object). Safe to run
-- twice or to inline into an ad-hoc psql session.

CREATE TABLE IF NOT EXISTS "oauth_application" (
  "id" text PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "icon" text,
  "metadata" text,
  "client_id" text NOT NULL,
  "client_secret" text,
  "redirect_urls" text NOT NULL,
  "type" text NOT NULL,
  "disabled" boolean DEFAULT false NOT NULL,
  "user_id" text,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL,
  CONSTRAINT "oauth_application_client_id_unique" UNIQUE("client_id"),
  CONSTRAINT "oauth_application_user_id_user_id_fk" FOREIGN KEY ("user_id")
    REFERENCES "user"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "oauth_application_user_id_idx"
  ON "oauth_application"("user_id");

CREATE TABLE IF NOT EXISTS "oauth_access_token" (
  "id" text PRIMARY KEY NOT NULL,
  "access_token" text NOT NULL,
  "refresh_token" text NOT NULL,
  "access_token_expires_at" timestamp NOT NULL,
  "refresh_token_expires_at" timestamp NOT NULL,
  "client_id" text NOT NULL,
  "user_id" text,
  "scopes" text NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL,
  CONSTRAINT "oauth_access_token_access_token_unique" UNIQUE("access_token"),
  CONSTRAINT "oauth_access_token_refresh_token_unique" UNIQUE("refresh_token"),
  CONSTRAINT "oauth_access_token_user_id_user_id_fk" FOREIGN KEY ("user_id")
    REFERENCES "user"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "oauth_access_token_client_id_idx"
  ON "oauth_access_token"("client_id");

CREATE INDEX IF NOT EXISTS "oauth_access_token_user_id_idx"
  ON "oauth_access_token"("user_id");

CREATE TABLE IF NOT EXISTS "oauth_consent" (
  "id" text PRIMARY KEY NOT NULL,
  "client_id" text NOT NULL,
  "user_id" text NOT NULL,
  "scopes" text NOT NULL,
  "consent_given" boolean NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL,
  CONSTRAINT "oauth_consent_user_id_user_id_fk" FOREIGN KEY ("user_id")
    REFERENCES "user"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "oauth_consent_client_id_idx"
  ON "oauth_consent"("client_id");

CREATE INDEX IF NOT EXISTS "oauth_consent_user_id_idx"
  ON "oauth_consent"("user_id");
