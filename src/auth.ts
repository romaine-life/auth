import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "./db/client.js";

const baseUrl = process.env.BASE_URL ?? "https://auth.romaine.life";

export const auth = betterAuth({
  baseURL: baseUrl,
  secret: process.env.BETTER_AUTH_SECRET,
  database: drizzleAdapter(db, { provider: "pg" }),

  // Apps that may call this auth service from a browser. Cookie scope is
  // `.romaine.life` so the session works across every subdomain.
  trustedOrigins: [
    "https://homepage.romaine.life",
    "https://workout.romaine.life",
    "https://plants.romaine.life",
    "https://invest.romaine.life",
    "https://house-hunt.romaine.life",
    "https://diagrams.romaine.life",
    "http://localhost:5173",
    "http://localhost:5500",
  ],

  advanced: {
    crossSubDomainCookies: {
      enabled: true,
      domain: "romaine.life",
    },
  },

  socialProviders: {
    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID!,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
      tenantId: "common",
    },
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
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
