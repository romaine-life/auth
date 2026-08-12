import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "./db/client.js";
import { getManagedOrigins } from "./managed-origins.js";
import { isReservedServiceEmail } from "./synthetic-email.js";
import { OAUTH_CLIENT_IDS, hashClientSecret } from "./oauth-clients.js";

/**
 * The platform claims every relying party authorizes from.
 *
 * `role` is what Grafana's `role_attribute_path` reads to decide Admin vs Viewer. `groups` mirrors
 * it as a single-element array because Argo CD's RBAC matches on a groups claim, so both authorize
 * off the same platform role without a bespoke mapping. `apps` is the per-user prefs blob, parsed
 * so the wire shape is an object rather than a JSON-encoded string.
 *
 * Shared by the id_token and userinfo hooks deliberately: they were one hook before the migration,
 * and letting them drift apart is how an RP ends up authorizing differently depending on which
 * surface it read.
 */
function platformClaims(user: Record<string, unknown>): Record<string, unknown> {
  let apps: Record<string, unknown> = {};
  try {
    apps = JSON.parse(typeof user.apps === "string" ? user.apps : "{}");
  } catch {
    // Bad JSON in the apps column must not break a token; same defence as definePayload above.
  }
  const role = typeof user.role === "string" ? user.role : "user";
  return { role, groups: [role], apps };
}

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
//      glimmung. See romaine-life/glimmung#142 for the cross-repo contract.
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
  // Per-project slot wildcards under `.dev.romaine.life` do not belong
  // in this list — they are reconciled into the managed_origin table
  // by glimmung. See romaine-life/glimmung#142, and the CI gate at
  // scripts/check-static-slot-origins.mjs that enforces this.
  "http://localhost:3000",
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
      prompt: "select_account",
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
      //
      // `service` is reserved for k8s service-principal users minted by
      // /api/auth/exchange/k8s (see src/service-exchange.ts). Apps that
      // accept service callers gate explicitly on role=service so a
      // human role and a service role can never share a route by
      // accident. See romaine-life/tank-operator#486.
      role: { type: "string", defaultValue: "pending" },
      // JSON blob for per-app preferences. Apps namespace under their own key,
      // e.g. apps.kill-me = { tdee: 2200 }. Apps that need richer per-user data
      // keep their own table keyed by user.id.
      apps: { type: "string", defaultValue: "{}" },
    },
  },

  databaseHooks: {
    user: {
      create: {
        // Refuse any user-create whose email is in a synthetic service
        // domain. Defense-in-depth against an IdP (Microsoft, Google)
        // returning an email under our reserved namespace and Better
        // Auth happily upserting it as a human row — that would collide
        // with the structurally-distinct row that /api/auth/exchange/k8s
        // intends to own. Service principals are inserted via raw
        // db.insert in service-exchange.ts and intentionally bypass this
        // hook.
        before: async (userData) => {
          const email = (userData as { email?: string }).email ?? "";
          if (isReservedServiceEmail(email)) {
            throw new Error(
              `email ${email} is in a reserved service-principal domain; ` +
                `human sign-in under this namespace is refused by construction`,
            );
          }
          return { data: userData };
        },
      },
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

    // OAuth2/OIDC authorization-server surface for relying parties that
    // cannot use the romaine.life-parent-domain session cookie. Grafana and
    // Argo CD use it as off-the-shelf RPs; ambience and chess-tactics use it
    // as first-party BFFs. Same-parent-domain apps may keep using the shared
    // session cookie + /api/auth/jwks.
    //
    // Mounted under /api/auth/* alongside the rest of Better Auth, so the
    // discovery doc is at /api/auth/.well-known/openid-configuration and
    // the authorize/token/userinfo endpoints are at /api/auth/oauth2/*.
    //
    // Migrated from the deprecated `oidcProvider` plugin, which had two defects its
    // own latest release still carries and never will not:
    //
    //   - refresh rotation without invalidation. The old plugin created a new token row
    //     and left the previous refresh token valid until its own expiry, so a replayed
    //     token produced no conflict and rotation bought nothing (RFC 9700 §4.14.2). It
    //     also re-stamped the expiry on every refresh, so an active chain never expired
    //     at all — which draft-ietf-oauth-browser-based-apps-26 §6.3.2.3-4 forbids.
    //   - `auth_time` emitted in MILLISECONDS where OIDC Core §2 requires seconds, so a
    //     relying party's freshness check saw a time in the far future and passed
    //     unconditionally.
    //
    // This plugin revokes the presented refresh token on rotation, invalidates the whole
    // family when a revoked one is replayed, carries the original `exp` forward instead
    // of extending it, and reports `auth_time` in seconds.
    oauthProvider({
      // Reuse the existing landing-page sign-in surface; an RP redirect that hits
      // `prompt=login` lands the user here, the Microsoft/Google buttons sign them in,
      // and the authorize flow resumes from the session cookie that gets set.
      loginPage: "/",
      // Every client registered here is first-party and skips consent, so this page is
      // never reached in practice. It is required by the plugin and pointing it at the
      // landing page keeps a mis-registered future client on a real page rather than a 404.
      consentPage: "/",
      // Ours, not the plugin's: clients are declared in code and reconciled at boot rather than
      // registered through an API, so the seeding path needs the same function. See
      // src/oauth-clients.ts for why an unsalted SHA-256 is the right primitive for a
      // machine-generated secret and would be the wrong one for a password.
      storeClientSecret: { hash: async (secret: string) => hashClientSecret(secret) },
      // Access and refresh tokens are hashed at rest, so a read of the token tables
      // yields nothing replayable — the same reasoning as Chess Tactics' own session
      // store (ADR-0576).
      storeTokens: "hashed",
      allowDynamicClientRegistration: false,
      allowUnauthenticatedClientRegistration: false,
      scopes: ["openid", "email", "profile", "offline_access"],
      accessTokenExpiresIn: 3600,
      // The authorization server's MAXIMUM, not any one app's session length. Chess
      // Tactics holds 90-day sessions (ADR-0576 decision 1) and renews beneath this;
      // Grafana and Argo CD each own their own, shorter, session policy
      // (`login_maximum_lifetime_duration` and Argo's own JWT expiry respectively).
      // Neither package offers a per-client lifetime, and this is why that is fine:
      // session length belongs to the relying party, the ceiling belongs here.
      refreshTokenExpiresIn: 60 * 60 * 24 * 90,
      // Held in memory so an authorize call costs no client lookup. The rows themselves
      // are reconciled at boot by `reconcileOAuthClients` in src/oauth-clients.ts —
      // clients are DATA in this plugin, where they were static config in the old one.
      cachedTrustedClients: new Set(OAUTH_CLIENT_IDS),
      // The platform claims every relying party's authorization depends on. The old
      // plugin fed both surfaces from one hook; this one splits them, and BOTH must be
      // wired or the failure is silent: Grafana reads `role` through
      // `role_attribute_path` and would quietly demote every user to Viewer, and Argo
      // CD matches RBAC on `groups` (`scopes: '[groups]'` → `g, admin, role:admin`) and
      // would match no rule at all. Nothing errors in either case.
      customIdTokenClaims: ({ user }) => platformClaims(user),
      customUserInfoClaims: ({ user }) => platformClaims(user),
    }),
  ],
});
