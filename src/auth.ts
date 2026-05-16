import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "./db/client.js";
import { getManagedOrigins } from "./managed-origins.js";

const baseUrl = process.env.BASE_URL ?? "https://auth.romaine.life";

// Cookie scope. Prod runs at auth.romaine.life and wants `.romaine.life` so
// every subdomain (homepage, workout, glimmung, etc.) shares the session.
// Test slots at *.auth.dev.romaine.life override this to
// `auth.dev.romaine.life` so slot cookies never set on prod's `.romaine.life`.
const cookieDomain = process.env.COOKIE_DOMAIN ?? "romaine.life";

// Test slots run with TEST_MODE=true and don't provide real OAuth/secret
// env. The server's request handlers branch on TEST_MODE before any
// Better Auth call, so this `auth` object is constructed but never used in
// test mode — we just need its init not to throw on missing env values.
const TEST_MODE = process.env.TEST_MODE === "true";
const TEST_PLACEHOLDER = "test-mode-only-not-a-real-credential";
const fromEnv = (key: string): string =>
  process.env[key] ?? (TEST_MODE ? TEST_PLACEHOLDER : "");

// trustedOrigins. Better Auth validates passed-in `callbackURL` values
// against this list, so a downstream app's cross-app sign-in redirect needs
// its origin here or signInSocial throws "Invalid callbackURL".
//
// Two sources of truth:
//   1. `PROD_TRUSTED_ORIGINS` (below): auth.romaine.life's known peer apps,
//      shipped as static config.
//   2. `managed_origin` table: per-project slot wildcards reconciled by
//      glimmung. See nelsong6/glimmung#142 for the cross-repo contract.
//
// `trustedOrigins` is registered as a function so the union is rebuilt at
// request time. `getManagedOrigins` caches DB reads for 60s in-process, so
// signInSocial doesn't pay a DB roundtrip per click.
//
// Test slots pass `TRUSTED_ORIGINS` (comma-separated) to bypass the
// PROD list entirely; in that mode we still union with the managed set so
// any project-owned slot wildcard remains valid even in a test slot.
const PROD_TRUSTED_ORIGINS = [
  "https://homepage.romaine.life",
  "https://workout.romaine.life",
  "https://investing.romaine.life",
  "https://diagrams.romaine.life",
  "https://tank.romaine.life",
  "https://fzt-frontend.romaine.life",
  "https://glimmung.romaine.life",
  // NOTE: `https://*.glimmung.dev.romaine.life` lived here historically. It
  // moves to the managed_origin table in nelsong6/glimmung#142 stage 4 —
  // do not re-add it here; the migration guard rejects static slot
  // wildcards under `.dev.romaine.life`.
  "https://*.glimmung.dev.romaine.life",
  "http://localhost:5173",
  "http://localhost:5500",
];
const staticTrustedOrigins = process.env.TRUSTED_ORIGINS
  ? process.env.TRUSTED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
  : PROD_TRUSTED_ORIGINS;

/** Exported for the CORS matcher in src/server.ts — same set, different
 *  consumer. Keep both reads aligned so a project can't pass callbackURL
 *  validation while failing the silent-exchange CORS preflight. */
export async function resolveAllTrustedOrigins(): Promise<string[]> {
  if (TEST_MODE) return staticTrustedOrigins;
  const managed = await getManagedOrigins();
  return [...staticTrustedOrigins, ...managed];
}

export const auth = betterAuth({
  baseURL: baseUrl,
  secret: process.env.BETTER_AUTH_SECRET ?? (TEST_MODE ? TEST_PLACEHOLDER : undefined),
  database: drizzleAdapter(db, { provider: "pg" }),

  trustedOrigins: resolveAllTrustedOrigins,

  advanced: {
    crossSubDomainCookies: {
      enabled: true,
      domain: cookieDomain,
    },
  },

  socialProviders: {
    microsoft: {
      clientId: fromEnv("MICROSOFT_CLIENT_ID"),
      clientSecret: fromEnv("MICROSOFT_CLIENT_SECRET"),
      tenantId: "common",
    },
    google: {
      clientId: fromEnv("GOOGLE_CLIENT_ID"),
      clientSecret: fromEnv("GOOGLE_CLIENT_SECRET"),
    },
  },

  user: {
    // Custom fields surface as columns in src/db/schema.ts. Keep both in sync.
    additionalFields: {
      // Platform role. `pending` is the default for any Microsoft account
      // that signs in cold — they exist in the user table but no app on
      // romaine.life accepts them until an admin promotes them via the
      // /admin console. This preserves the allowlist behavior we used to
      // get from `romaine-life-admin-emails` without the per-app KV mount.
      role: { type: "string", defaultValue: "pending" },
      // JSON blob for per-app preferences. Apps namespace under their own key,
      // e.g. apps.kill-me = { tdee: 2200 }. Apps that need richer per-user data
      // keep their own table keyed by user.id.
      apps: { type: "string", defaultValue: "{}" },
    },
  },

  plugins: [
    // Issues RS256-signed JWTs; exposes JWKS at /api/auth/jwks. Apps verify
    // against that URL (no shared secret distributed).
    //
    // `definePayload` pins the JWT shape that romaine.life apps depend on:
    // sub/email/name come from Better Auth's user record, role is the
    // platform-wide authorization claim (admin|user), and apps is the parsed
    // per-user app-prefs blob. Without this, the default payload would carry
    // every user-table column (image, createdAt, password hashes if any) and
    // `apps` would be a JSON-encoded string instead of an object — both
    // make the wire shape ugly for downstream verifiers. `sub` is overridden
    // by Better Auth's getSubject after this returns, so we set email/role/
    // etc. here and let the plugin stamp sub.
    jwt({
      jwks: {
        keyPairConfig: { alg: "RS256" },
      },
      jwt: {
        definePayload: ({ user }) => {
          const u = user as typeof user & { role?: string; apps?: string };
          let apps: Record<string, unknown> = {};
          try {
            apps = JSON.parse(u.apps ?? "{}");
          } catch {
            // Bad JSON in apps column shouldn't break sign-in. Default to
            // empty so the claim shape stays consistent.
          }
          return {
            email: u.email,
            name: u.name,
            role: u.role ?? "user",
            apps,
          };
        },
      },
    }),
  ],
});
