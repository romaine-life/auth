// Emit the OAuth provider's DDL from Better Auth's own generator.
//
// The tables must match what the plugin expects exactly, and "exactly" is not something to
// hand-write from reading a schema object. `compileMigrations` produces the same SQL the runtime
// would apply, so the migration in drizzle/ is generated from the source of truth rather than
// transcribed from it.
//
// Usage: node scripts/emit-oauth-migration.mjs > drizzle/0002-oauth-provider.generated.sql

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { KyselyPGlite } from "kysely-pglite";
import { createHash } from "node:crypto";

const { dialect } = await KyselyPGlite.create();

const auth = betterAuth({
  baseURL: "http://localhost:3000",
  secret: "schema-generation-only",
  database: { dialect, type: "postgres" },
  user: {
    additionalFields: {
      role: { type: "string", defaultValue: "pending" },
      apps: { type: "string", defaultValue: "{}" },
    },
  },
  plugins: [
    jwt({ jwks: { keyPairConfig: { alg: "RS256" } } }),
    oauthProvider({
      loginPage: "/",
      consentPage: "/",
      storeClientSecret: { hash: async (s) => createHash("sha256").update(s).digest("hex") },
      storeTokens: "hashed",
      allowDynamicClientRegistration: false,
      scopes: ["openid", "email", "profile", "offline_access"],
    }),
  ],
});

const { compileMigrations } = await getMigrations(auth.options);
const sql = await compileMigrations();
process.stdout.write(sql.endsWith("\n") ? sql : `${sql}\n`);
