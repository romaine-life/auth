import { pgTable, text, timestamp, boolean, integer, jsonb, uniqueIndex } from "drizzle-orm/pg-core";

// Schema matches Better Auth's expected tables (regenerate with
// `npx @better-auth/cli generate` if the auth.ts config gains plugins
// that add tables). Custom fields on `user` are declared in auth.ts
// under `user.additionalFields` and surface here as columns.

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  name: text("name").notNull(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  // Custom fields — keep in sync with auth.ts `user.additionalFields`.
  role: text("role").notNull().default("pending"),
  apps: text("apps").notNull().default("{}"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const session = pgTable("session", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const account = pgTable("account", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: timestamp("access_token_expires_at"),
  refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
  scope: text("scope"),
  password: text("password"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const verification = pgTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

// Browser-approved CLI/device grants. A local CLI starts a pending request,
// an admin approves it in their existing auth.romaine.life browser session,
// and the CLI exchanges either its device_code or the one-time callback code
// for the same 24h bot token minted by /admin/bot-tokens.
export const cliDeviceGrant = pgTable(
  "cli_device_grant",
  {
    id: text("id").primaryKey(),
    deviceCodeHash: text("device_code_hash").notNull(),
    userCodeHash: text("user_code_hash").notNull(),
    exchangeCodeHash: text("exchange_code_hash"),
    // Legacy OAuth-style column name. It stores versioned JSON metadata for
    // requester display fields and optional approver-supplied values.
    clientName: text("client_name").notNull(),
    redirectUri: text("redirect_uri"),
    state: text("state"),
    codeChallenge: text("code_challenge"),
    codeChallengeMethod: text("code_challenge_method"),
    status: text("status").notNull().default("pending"),
    approvedByUserId: text("approved_by_user_id").references(() => user.id, { onDelete: "set null" }),
    approvedByEmail: text("approved_by_email"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    expiresAt: timestamp("expires_at").notNull(),
    approvedAt: timestamp("approved_at"),
    consumedAt: timestamp("consumed_at"),
  },
  (table) => ({
    deviceCodeHashUnique: uniqueIndex("cli_device_grant_device_code_hash_unique").on(
      table.deviceCodeHash,
    ),
    userCodeHashUnique: uniqueIndex("cli_device_grant_user_code_hash_unique").on(
      table.userCodeHash,
    ),
    exchangeCodeHashUnique: uniqueIndex("cli_device_grant_exchange_code_hash_unique").on(
      table.exchangeCodeHash,
    ),
  }),
);

// OAuth 2.1 provider (@better-auth/oauth-provider). Replaces the deprecated `oidcProvider`
// plugin, whose tables are renamed to `*_legacy` by drizzle/0002 and dropped once the rollout is
// confirmed. Two defects motivated the change and neither was fixable in place: refresh rotation
// that never invalidated the previous token (RFC 9700 §4.14.2), and `auth_time` emitted in
// milliseconds where OIDC Core §2 requires seconds.
//
// Better Auth resolves each model to the table exported under the SAME NAME here, so these export
// names are load-bearing: `oauthClient` must be `oauthClient`. The physical names stay snake_case
// to match every other table in this database. That mapping is exactly what the generated DDL
// does NOT know about — see scripts/emit-oauth-migration.mjs and the parity test that pins it.
//
// `string[]` fields are jsonb, which is what the generator emits and what the drizzle adapter
// reads back as arrays.
export const oauthClient = pgTable("oauth_client", {
  id: text("id").primaryKey(),
  clientId: text("client_id").notNull().unique(),
  clientSecret: text("client_secret"),
  disabled: boolean("disabled").default(false),
  skipConsent: boolean("skip_consent"),
  enableEndSession: boolean("enable_end_session"),
  subjectType: text("subject_type"),
  scopes: jsonb("scopes").$type<string[]>(),
  userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  name: text("name"),
  uri: text("uri"),
  icon: text("icon"),
  contacts: jsonb("contacts").$type<string[]>(),
  tos: text("tos"),
  policy: text("policy"),
  softwareId: text("software_id"),
  softwareVersion: text("software_version"),
  softwareStatement: text("software_statement"),
  redirectUris: jsonb("redirect_uris").$type<string[]>().notNull(),
  postLogoutRedirectUris: jsonb("post_logout_redirect_uris").$type<string[]>(),
  tokenEndpointAuthMethod: text("token_endpoint_auth_method"),
  grantTypes: jsonb("grant_types").$type<string[]>(),
  responseTypes: jsonb("response_types").$type<string[]>(),
  public: boolean("public"),
  type: text("type"),
  requirePKCE: boolean("require_pkce"),
  referenceId: text("reference_id"),
  metadata: jsonb("metadata"),
});

// `revoked` is the column the whole migration is for. Rotation stamps it on the token just
// presented; presenting a stamped token again revokes the entire family for that (client, user),
// which is what makes rotation detect replay instead of merely issuing new strings.
export const oauthRefreshToken = pgTable("oauth_refresh_token", {
  id: text("id").primaryKey(),
  token: text("token").notNull().unique(),
  clientId: text("client_id").notNull().references(() => oauthClient.clientId, { onDelete: "cascade" }),
  sessionId: text("session_id").references(() => session.id, { onDelete: "set null" }),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  referenceId: text("reference_id"),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  revoked: timestamp("revoked"),
  authTime: timestamp("auth_time"),
  scopes: jsonb("scopes").$type<string[]>().notNull(),
});

export const oauthAccessToken = pgTable("oauth_access_token", {
  id: text("id").primaryKey(),
  token: text("token").notNull().unique(),
  clientId: text("client_id").notNull().references(() => oauthClient.clientId, { onDelete: "cascade" }),
  sessionId: text("session_id").references(() => session.id, { onDelete: "set null" }),
  userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
  referenceId: text("reference_id"),
  refreshId: text("refresh_id").references(() => oauthRefreshToken.id, { onDelete: "cascade" }),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  scopes: jsonb("scopes").$type<string[]>().notNull(),
});

export const oauthConsent = pgTable("oauth_consent", {
  id: text("id").primaryKey(),
  clientId: text("client_id").notNull().references(() => oauthClient.clientId, { onDelete: "cascade" }),
  userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
  referenceId: text("reference_id"),
  scopes: jsonb("scopes").$type<string[]>().notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

// JWT plugin: stores the RSA keypair used to sign JWTs. JWKS at
// /api/auth/jwks serves the public key; apps verify against that URL.
// Field names match the plugin's expected JS property names (publicKey,
// privateKey, etc.) — the underlying DB columns are snake_case per the
// usual Drizzle convention. `expiresAt` is optional and supports future
// key rotation; the plugin only writes it when rotation is enabled.
export const jwks = pgTable("jwks", {
  id: text("id").primaryKey(),
  publicKey: text("public_key").notNull(),
  privateKey: text("private_key").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  expiresAt: timestamp("expires_at"),
});

// Glimmung-managed slot origin allowlist. Each row contributes one entry
// to Better Auth's `trustedOrigins` and Hono's CORS allowlist on
// `/api/auth/*`. Owned by glimmung's reconciler — see romaine-life/glimmung#142.
//
// `project` is glimmung's project name (e.g. "tank-operator", "glimmung").
// `wildcard` is a host pattern like "https://*.tank.dev.romaine.life" —
// validated at write time in src/managed-origins.ts.
//
// Uniqueness on (project, wildcard) prevents accidental duplicates from
// repeated upserts; glimmung's reconciler uses replace-set semantics, so a
// project's wildcard list is whatever the latest PUT installed.
export const managedOrigin = pgTable(
  "managed_origin",
  {
    id: text("id").primaryKey(),
    project: text("project").notNull(),
    wildcard: text("wildcard").notNull(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => ({
    projectWildcardUnique: uniqueIndex("managed_origin_project_wildcard_unique").on(
      table.project,
      table.wildcard,
    ),
  }),
);
