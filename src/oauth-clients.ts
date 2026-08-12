// The OAuth clients this authorization server serves, and the boot-time reconciliation that
// puts them in the database.
//
// The deprecated `oidcProvider` plugin took clients as static config (`trustedClients`).
// `@better-auth/oauth-provider` treats them as DATA — rows in `oauth_client` — so this module is
// what keeps "which relying parties exist" declared in code while satisfying a plugin that reads
// them from a table.
//
// Reconciliation runs on every pod start and is idempotent: it inserts what is missing and
// updates what has drifted, and never deletes. Deleting a client would sever every live session
// belonging to it, and a rollout that briefly runs an older image must not do that to the newer
// image's clients.

import { createHash } from "node:crypto";

/**
 * How a client secret is stored.
 *
 * The plugin can hash secrets itself, but then only its own registration endpoints can write a
 * client — and ours are declared in code and reconciled at boot, not registered through an API.
 * Owning the function keeps seeding explicit and keeps this file independent of the plugin's
 * internal hashing, which is not part of its public surface.
 *
 * SHA-256 with no salt is deliberate and correct here, where it would be wrong for a password: a
 * client secret is 256 bits of machine-generated randomness, not a human-chosen string, so there
 * is no dictionary to attack and nothing for a salt or a work factor to buy. What this defends is
 * a database read, and a preimage of SHA-256 over a random 256-bit input is not available.
 */
export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

/** A client's declared shape. `secretEnv` is read at reconcile time, never committed. */
export interface OAuthClientDeclaration {
  clientId: string;
  name: string;
  redirectUris: string[];
  /** Public clients authenticate with PKCE alone; confidential ones also present a secret. */
  isPublic: boolean;
  /** Environment variable holding the secret, for confidential clients only. */
  secretEnv?: string;
  /**
   * First-party apps skip consent: the same person has already consented to using their
   * romaine.life identity by signing in here, and bouncing them through a consent page for an
   * internal tool is friction with no security value.
   */
  skipConsent: boolean;
}

export const OAUTH_CLIENTS: OAuthClientDeclaration[] = [
  {
    clientId: "grafana",
    name: "Grafana",
    // Confidential: Grafana holds a secret from Key Vault and is not a browser app.
    isPublic: false,
    secretEnv: "OIDC_GRAFANA_CLIENT_SECRET",
    redirectUris: ["https://grafana.romaine.life/login/generic_oauth"],
    skipConsent: true,
  },
  {
    clientId: "argocd",
    name: "Argo CD",
    // Public: Argo CD talks to us directly as a native OIDC relying party
    // (configs.cm `oidc.config`, enablePKCEAuthentication: true), not through its bundled Dex.
    // It only supports PKCE as a public client, so the code challenge — not a secret —
    // authenticates the exchange. Dex stays deployed solely for the mcp-argocd SA-token
    // exchange; it is not in this human-login path.
    isPublic: true,
    redirectUris: [
      "https://argocd.romaine.life/auth/callback",
      // The `argocd login --sso` CLI loopback.
      "http://localhost:8085/auth/callback",
    ],
    skipConsent: true,
  },
  {
    clientId: "ambience",
    name: "Ambience",
    // Public: ambience-authority's backend does the code exchange and verifies the id_token
    // (aud="ambience", iss=https://auth.romaine.life). Replaced a standalone single-tenant
    // Entra app registration that rejected personal Microsoft accounts.
    isPublic: true,
    redirectUris: ["https://ambience.romaine.life/auth/callback"],
    skipConsent: true,
  },
  {
    clientId: "chess-tactics",
    name: "Chess Tactics",
    // CONFIDENTIAL as of ADR-0576. Chess Tactics is a Backend-For-Frontend, and
    // draft-ietf-oauth-browser-based-apps-26 §6.1.3.1 says a BFF MUST act as a confidential
    // client. It was registered public, which PKCE made safe against code interception but
    // which proves nothing about WHICH application is redeeming a code.
    isPublic: false,
    secretEnv: "OIDC_CHESS_TACTICS_CLIENT_SECRET",
    redirectUris: ["https://chess-tactics.com/api/auth/callback"],
    skipConsent: true,
  },
];

export const OAUTH_CLIENT_IDS = OAUTH_CLIENTS.map((client) => client.clientId);

/**
 * Just enough of a Better Auth instance to reconcile clients.
 *
 * `Auth` is generic over the whole options object, so naming it here would bind this module to one
 * exact configuration and break the moment a plugin is added. Structural typing keeps it honest:
 * this needs an adapter and nothing else.
 */
interface AdapterWhere { field: string; value: unknown }

export interface AuthWithAdapter {
  $context: Promise<{
    adapter: {
      findOne: <T>(data: { model: string; where: AdapterWhere[] }) => Promise<T | null>;
      create: <T>(data: { model: string; data: Record<string, unknown> }) => Promise<T>;
      update: <T>(data: {
        model: string;
        where: AdapterWhere[];
        update: Record<string, unknown>;
      }) => Promise<T | null>;
    };
  }>;
}

type ClientRow = {
  clientId: string;
  name: string;
  clientSecret: string | null;
  redirectUris: string[];
  public: boolean;
  skipConsent: boolean;
  disabled: boolean;
  type: string;
  requirePKCE: boolean;
  createdAt: Date;
  updatedAt: Date;
};

/**
 * Put the declared clients in the database, idempotently.
 *
 * Called once at startup, before the server accepts traffic.
 *
 * A confidential client whose secret is absent is registered PUBLIC with an error logged, rather
 * than aborting startup — see the comment at that branch for why refusing to start is the more
 * dangerous choice when one process is the authorization server for everything.
 */
export async function reconcileOAuthClients(
  auth: AuthWithAdapter,
  { testMode = false }: { testMode?: boolean } = {},
): Promise<void> {
  const { adapter: db } = await auth.$context;

  for (const client of OAUTH_CLIENTS) {
    let secret: string | null = null;
    let confidential = !client.isPublic;
    if (confidential) {
      secret = process.env[client.secretEnv ?? ""] ?? null;
      if (!secret) {
        // A missing secret must NOT take the authorization server down.
        //
        // The tempting answer is to throw: refusing to register a confidential client as one
        // anybody could impersonate sounds like the safe failure. It is the opposite here. This
        // process serves Grafana, Argo CD, ambience and Chess Tactics; exiting because ONE
        // client's secret has not been provisioned yet takes sign-in away from all of them —
        // including the tools you would use to fix it.
        //
        // Registering it public instead is not a downgrade from anything: it is exactly what that
        // client is today, and the alternative is not "more secure", it is "no authorization
        // server". So the client stays as it stands, loudly, and the next pod start after the
        // secret is provisioned upgrades it. A deliberate deployment-ordering allowance, matching
        // the one ADR-0576 makes on the Chess Tactics side, and removable once every secret ships.
        confidential = false;
        if (!testMode) {
          console.error(
            `[oauth-clients] ${client.clientId} is declared confidential but ${client.secretEnv} `
            + "is unset; registering it PUBLIC for now. Provision the secret and restart to "
            + "complete the upgrade.",
          );
        }
      }
    }

    const desired = {
      clientId: client.clientId,
      name: client.name,
      redirectUris: client.redirectUris,
      public: !confidential,
      skipConsent: client.skipConsent,
      disabled: false,
      type: confidential ? "web" : "public",
      // PKCE is required of every client here, confidential ones included. It costs a
      // confidential client nothing and closes code interception independently of the secret.
      requirePKCE: true,
      ...(secret ? { clientSecret: hashClientSecret(secret) } : {}),
    };

    const existing = await db.findOne<ClientRow>({
      model: "oauthClient",
      where: [{ field: "clientId", value: client.clientId }],
    });

    if (!existing) {
      await db.create<ClientRow>({
        model: "oauthClient",
        data: { ...desired, createdAt: new Date(), updatedAt: new Date() },
      });
      continue;
    }

    // Update rather than replace: the row's id is referenced by live refresh tokens, access
    // tokens and consents. Recreating it would take out every session that client holds.
    await db.update<ClientRow>({
      model: "oauthClient",
      where: [{ field: "clientId", value: client.clientId }],
      update: { ...desired, updatedAt: new Date() },
    });
  }
}
