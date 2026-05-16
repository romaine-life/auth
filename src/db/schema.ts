import { pgTable, text, timestamp, boolean, integer, uniqueIndex } from "drizzle-orm/pg-core";

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
// `/api/auth/*`. Owned by glimmung's reconciler — see nelsong6/glimmung#142.
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
