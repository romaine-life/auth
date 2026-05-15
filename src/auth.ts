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
      role: { type: "string", defaultValue: "user" },
      // JSON blob for per-app preferences. Apps namespace under their own key,
      // e.g. apps.kill-me = { tdee: 2200 }. Apps that need richer per-user data
      // keep their own table keyed by user.id.
      apps: { type: "string", defaultValue: "{}" },
    },
  },

  plugins: [
    // Issues RS256-signed JWTs; exposes JWKS at /api/auth/jwks. Apps verify
    // against that URL (no shared secret distributed).
    jwt({
      jwks: {
        keyPairConfig: { alg: "RS256" },
      },
    }),
  ],
});
