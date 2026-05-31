import { betterAuth } from "better-auth";
import { jwt, oidcProvider } from "better-auth/plugins";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "./db/client.js";
import { getManagedOrigins } from "./managed-origins.js";
import { isReservedServiceEmail } from "./synthetic-email.js";

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
  // Per-project slot wildcards under `.dev.romaine.life` do not belong
  // in this list — they are reconciled into the managed_origin table
  // by glimmung. See nelsong6/glimmung#142, and the CI gate at
  // scripts/check-static-slot-origins.mjs that enforces this.
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
      //
      // `service` is reserved for k8s service-principal users minted by
      // /api/auth/exchange/k8s (see src/service-exchange.ts). Apps that
      // accept service callers gate explicitly on role=service so a
      // human role and a service role can never share a route by
      // accident. See nelsong6/tank-operator#486.
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

    // OAuth2/OIDC authorization-server surface for off-the-shelf relying
    // parties that can't speak the romaine.life-native cookie/JWKS pattern.
    // First consumer: Grafana at grafana.romaine.life. Future likely
    // consumer: Argo CD UI. First-party romaine.life apps (homepage,
    // workout, glimmung, tank-operator) keep using the shared session
    // cookie + /api/auth/jwks — they don't go through these endpoints.
    //
    // Mounted under /api/auth/* alongside the rest of Better Auth, so the
    // discovery doc is at /api/auth/.well-known/openid-configuration and
    // the authorize/token/userinfo endpoints are at /api/auth/oauth2/*.
    // RPs configure these URLs explicitly (Grafana doesn't autodiscover),
    // so the non-root prefix doesn't matter.
    //
    // `useJWTPlugin: true` is the load-bearing flag: id_tokens are signed
    // with the same RS256 key the JWT plugin manages, so an RP can verify
    // id_tokens against /api/auth/jwks — identical to how an MCP server
    // verifies a bot token. One JWKS, one trust root, both paths.
    //
    // `trustedClients` registers Grafana statically without a DB row.
    // Adding a future RP is a 6-line append here + a KV secret + a deploy.
    // We deliberately do NOT enable dynamic client registration — there is
    // no scenario today where an unknown party should be able to mint
    // itself an OAuth client against this provider.
    //
    // Note: this plugin is marked @deprecated upstream in favor of
    // @better-auth/oauth-provider (not yet published for v1.6). Track the
    // migration when 2.0 lands. Removal is gated on a major version bump
    // so there is no urgency.
    oidcProvider({
      // Reuse the existing landing-page sign-in surface; an RP redirect
      // that hits `prompt=login` lands the user here, the Microsoft/Google
      // buttons sign them in, and the OIDC authorize flow resumes from the
      // session cookie that gets set.
      loginPage: "/",
      useJWTPlugin: true,
      requirePKCE: true,
      allowPlainCodeChallengeMethod: false,
      storeClientSecret: "hashed",
      allowDynamicClientRegistration: false,
      scopes: ["openid", "email", "profile"],
      accessTokenExpiresIn: 3600,
      refreshTokenExpiresIn: 60 * 60 * 24 * 7,
      // Surface the platform `role` claim + the `apps` per-user prefs blob
      // on the id_token and the /oauth2/userinfo response. Matches the JWT
      // plugin's `definePayload` shape above so an RP's role-mapping
      // expression is identical whether the JWT came from an OIDC login
      // (browser path) or a bot/service token (API path). `role` is what
      // Grafana's role_attribute_path reads to decide Admin vs Viewer.
      getAdditionalUserInfoClaim: (user) => {
        const u = user as typeof user & { role?: string; apps?: string };
        let apps: Record<string, unknown> = {};
        try {
          apps = JSON.parse(u.apps ?? "{}");
        } catch {
          // Bad JSON in apps column shouldn't break the id_token; same
          // defense as the JWT plugin's definePayload above.
        }
        return {
          role: u.role ?? "user",
          // `groups` mirrors `role` as a single-element array. Grafana reads
          // `role` directly via role_attribute_path; Argo CD's RBAC matches
          // on a groups claim (`scopes: '[groups]'` → `g, admin, role:admin`),
          // so surfacing the role here as `groups` lets Argo CD authorize off
          // the same platform role without a bespoke claim mapping.
          groups: [u.role ?? "user"],
          apps,
        };
      },
      trustedClients: [
        {
          clientId: "grafana",
          clientSecret: fromEnv("OIDC_GRAFANA_CLIENT_SECRET"),
          name: "Grafana",
          type: "web",
          metadata: null,
          disabled: false,
          redirectUrls: ["https://grafana.romaine.life/login/generic_oauth"],
          // First-party app; no consent screen on first login. The same
          // user has already consented to using their romaine.life identity
          // simply by signing into auth.romaine.life — bouncing them
          // through a consent page for an internal tool is friction with
          // no security value.
          skipConsent: true,
        },
        {
          clientId: "argocd",
          // Public client — no secret. Argo CD talks to us DIRECTLY as a
          // native OIDC relying party (configs.cm `oidc.config`,
          // enablePKCEAuthentication: true), exactly like Grafana, not
          // proxied through its bundled Dex. Argo CD only supports PKCE as a
          // public client, and our provider requires PKCE, so the code
          // challenge — not a client secret — authenticates the exchange.
          // (Dex stays deployed solely for the mcp-argocd SA-token exchange
          // via the aks-sa connector; it is not in this human-login path.)
          type: "public",
          name: "Argo CD",
          metadata: null,
          disabled: false,
          // Argo CD's native OIDC callback (NOT the /api/dex/callback used by
          // the old Dex-proxied setup). It autodiscovers our endpoints from
          // the root discovery doc. The localhost entry is the `argocd login
          // --sso` CLI loopback.
          redirectUrls: [
            "https://argocd.romaine.life/auth/callback",
            "http://localhost:8085/auth/callback",
          ],
          skipConsent: true,
        },
      ],
    }),
  ],
});
