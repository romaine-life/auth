// k8s SA-token → auth.romaine.life service-principal JWT exchange.
//
// Routes the inbound bearer through the existing k8s-auth verifier,
// resolves the bound pod's lineage annotations, idempotently upserts a
// Better Auth user under a reserved synthetic-email domain, and mints
// a standard auth.romaine.life JWT through the shared `mintAuthJwt`
// helper (src/mint-jwt.ts).
//
// The issued JWT is shaped exactly like a human auth.romaine.life JWT
// (same `iss`, `aud`, JWKS-published signing key) so downstream apps can
// verify it with their existing JWKS-backed validators. The only
// difference is `role=service` and an additional `actor_email` claim
// carrying the human whose session this pod is serving.
//
// See nelsong6/tank-operator#486 for the full plan.

import { eq } from "drizzle-orm";
import { db } from "./db/client.js";
import { user } from "./db/schema.js";
import { parseAllowlist, verifyK8sSAToken } from "./k8s-auth.js";
import { readPodLineage, type PodLineage } from "./k8s-pod.js";
import { mintAuthJwt } from "./mint-jwt.js";
import { buildServiceEmail, buildServiceName } from "./synthetic-email.js";
import {
  ExchangeError,
  isPlausibleActorEmail,
  serviceUserId,
  type ExchangeFailureReason,
} from "./service-exchange-helpers.js";

// Re-export so callers don't need to know about the helpers split.
export {
  ExchangeError,
  serviceUserId,
  type ExchangeFailureReason,
};

/** Per-consumer lineage policy.
 *
 *  - `per-session` (default for per-user pods like tank-operator's
 *    session pods): the pod carries `tank-operator/owner-email` +
 *    `tank-operator/session-id` annotations. readPodLineage reads them
 *    at exchange time; actor_email = owner-email; sessionId = session-id.
 *    Each exchange produces a JWT whose synthetic identity is specific
 *    to the human-and-session pair.
 *
 *  - `pod-stable` (shared MCP servers like mcp-glimmung): there is no
 *    per-pod human actor — the deployment is a platform-wide
 *    infrastructure component that serves many users. The exchange
 *    skips annotation reads and uses a fixed `stableId` configured
 *    here. actor_email collapses to the synthetic email (the service
 *    IS the actor), so glimmung's audit log says "this call came from
 *    mcp-glimmung" rather than naming a specific user. Per-request
 *    user attribution is a future enhancement that would forward the
 *    caller's identity through the MCP layer (kept out of scope per
 *    the design note on the glimmung-side cutover PR).
 */
/** Optional `pod-stable` capability: when true, the consumer's caller
 *  may supply a chosen `actor_email` on the exchange request. The
 *  synthetic identity (sub/email/name) stays based on stableId — only
 *  the `actor_email` claim changes — so audit logs still attribute
 *  the call to the orchestrator-as-issuer, with the on-behalf-of
 *  user named in `actor_email`.
 *
 *  Today this is set ONLY on the `tank-operator` orchestrator entry.
 *  The orchestrator forwards a SPA user's email when it needs to make
 *  a per-user MCP call (today: mcp-github → list a user's installation
 *  repos for the session-creation picker). Other in-cluster services
 *  (mcp-k8s, mcp-argocd, etc.) have no such use case and stay
 *  un-elevated by default. */
type ConsumerConfig =
  | { slug: string; mode: "per-session" }
  | {
      slug: string;
      mode: "pod-stable";
      stableId: string;
      /** When true, the route handler may forward a caller-supplied
       *  actor_email to the mint. Defaults to false. */
      allowActorOverride?: boolean;
    };

/** Map from k8s namespace to consumer config. Each consumer slug must
 *  have a matching subdomain registered in RESERVED_SERVICE_EMAIL_DOMAINS
 *  in src/synthetic-email.ts. Add a row here when onboarding a new
 *  consumer AND extend RESERVED_SERVICE_EMAIL_DOMAINS — both are
 *  required, by construction (buildServiceEmail refuses unregistered
 *  consumers). */
const NAMESPACE_TO_CONSUMER: Record<string, ConsumerConfig> = {
  "tank-operator-sessions": { slug: "tank", mode: "per-session" },
  "mcp-k8s": {
    slug: "mcp-k8s",
    mode: "pod-stable",
    stableId: "mcp-k8s",
  },
  "mcp-argocd": {
    slug: "mcp-argocd",
    mode: "pod-stable",
    stableId: "mcp-argocd",
  },
  "mcp-azure-personal": {
    slug: "mcp-azure-personal",
    mode: "pod-stable",
    stableId: "mcp-azure-personal",
  },
  // Hermes (`nelsong6/hermes`) — singleton AI-agent StatefulSet
  // calling tank-operator's MCP servers (mcp-github, mcp-tank-operator,
  // mcp-glimmung) from its own pod. No per-pod human actor: one
  // Hermes pod serves every user with hermes-access. Per-request user
  // attribution through the MCP layer is the same out-of-scope
  // enhancement called out on the other pod-stable consumers above.
  // See nelsong6/tank-operator#540.
  hermes: {
    slug: "hermes",
    mode: "pod-stable",
    stableId: "hermes",
  },
  // Tank-operator's orchestrator (the long-lived Deployment in the
  // `tank-operator` namespace). Distinct from `tank-operator-sessions`
  // above, which keys per-session lineage from pod annotations: this
  // entry is the orchestrator itself, calling out to Hermes' API server
  // for hermes_gui session turns (#540 follow-up). Two distinct slugs
  // by design — a leaked session JWT (subdomain `service.tank...`) and
  // a leaked orchestrator JWT (subdomain `service.tank-operator...`)
  // are not interchangeable in any downstream verifier. stableId is
  // fixed at `orchestrator` because there's only ever one logical
  // orchestrator identity per deployment; pod restarts on the same
  // Deployment continue to mint under the same synthetic user row.
  "tank-operator": {
    slug: "tank-operator",
    mode: "pod-stable",
    stableId: "orchestrator",
    // Stage 2 of the per-session repo-selection feature
    // (nelsong6/tank-operator stage 2): the orchestrator needs to call
    // mcp-github to enumerate a SPA user's installation repos for the
    // splash-page picker, but the orchestrator pod is not bound to any
    // one user. By design we don't move GitHub App credentials back into
    // the orchestrator (that would undo the mcp-github extraction). The
    // alternative is to let mcp-github keep its existing actor_email →
    // installation_id lookup, and let the orchestrator mint a service
    // JWT with the SPA caller's email in actor_email. This flag opens
    // that minting path for the orchestrator's namespace ONLY. mcp-github
    // sees a normal service JWT — no custom side-channel — and routes
    // it to the right installation. See nelsong6/tank-operator stage 2
    // PR for the full chain.
    allowActorOverride: true,
  },
};

const ROLE = "service" as const;

/** Audience pinned on inbound SA tokens. Mirrors the admin path's pin so a
 *  stolen SA token cannot be replayed against any other JWT-validating
 *  service in the cluster. Session-pod helm chart must mount its
 *  projected token with `audience: <this>`. */
const DEFAULT_SERVICE_AUDIENCE = "https://auth.romaine.life";

let cachedAllowlist: Set<string> | null = null;

function getAllowlist(): Set<string> {
  if (cachedAllowlist) return cachedAllowlist;
  cachedAllowlist = parseAllowlist(process.env.K8S_SERVICE_SA_ALLOWLIST ?? "");
  return cachedAllowlist;
}

function getAudience(): string {
  return (process.env.K8S_SERVICE_AUDIENCE ?? DEFAULT_SERVICE_AUDIENCE).trim();
}

/** Test-only: clear the cached allowlist so a test can re-init from env. */
export function _resetServiceExchangeCache(): void {
  cachedAllowlist = null;
}

export interface ExchangeResult {
  token: string;
  userId: string;
  email: string;
  actorEmail: string;
  sessionId: string;
  /** Seconds-since-epoch when the JWT expires. Mirrors the JWT's `exp`
   *  claim; surfaced so callers (session-pod bootstrap) can schedule a
   *  pre-expiry refresh without re-parsing the JWT. Default 15 min per
   *  Better Auth's expirationTime. */
  expiresAt: number;
}

/** Optional inputs the route handler can forward to the exchange.
 *  Today the only field is the on-behalf-of `requestedActorEmail` used
 *  by the tank-operator orchestrator stage 2 flow. Kept as a struct so
 *  future per-call knobs (forwarded by trusted callers) have a place
 *  to land without growing the positional arity. */
export interface ExchangeOptions {
  /** Caller-supplied `actor_email` override. When present AND the
   *  exchanging consumer carries `allowActorOverride: true`, the minted
   *  JWT carries this string as `actor_email` instead of the consumer's
   *  synthetic identity. The synthetic sub/email/name are unchanged —
   *  audit logs still attribute the call to the orchestrator-as-issuer.
   *
   *  Requests from non-elevated consumers fail with
   *  `denied_actor_override_not_allowed`; malformed inputs fail with
   *  `denied_actor_email_invalid`. Both are the route-handler's
   *  surface; downstream consumers (mcp-github, etc.) never see this
   *  field directly. */
  requestedActorEmail?: string;
}

/** Exchange a verified k8s ServiceAccount JWT for an auth.romaine.life
 *  service-principal JWT. Throws `ExchangeError` on any failure with a
 *  stable telemetry reason and an appropriate HTTP status for the route
 *  handler to surface. */
export async function exchangeServiceAccountToken(
  saToken: string,
  options: ExchangeOptions = {},
): Promise<ExchangeResult> {
  // 1. Verify the inbound SA JWT.
  let verified;
  try {
    verified = await verifyK8sSAToken(saToken, {
      audience: getAudience(),
      allowlist: getAllowlist(),
    });
  } catch (e) {
    const msg = (e as Error).message;
    if (msg.includes("not in allowlist")) {
      throw new ExchangeError(msg, 403, "denied_allowlist");
    }
    throw new ExchangeError(msg, 401, "denied_token");
  }

  // 2. Refuse tokens with no bound pod ref — without a pod we cannot
  //    resolve lineage, and an unscoped service-principal JWT is exactly
  //    the failure mode the design forbids.
  if (!verified.pod) {
    throw new ExchangeError(
      "SA token has no kubernetes.io.pod ref; mount the projected SA token with a Pod owner reference",
      400,
      "denied_unbound_pod",
    );
  }

  // 3. Map namespace → consumer slug.
  const consumer = NAMESPACE_TO_CONSUMER[verified.namespace];
  if (!consumer) {
    throw new ExchangeError(
      `namespace ${verified.namespace} has no consumer mapping; add it to NAMESPACE_TO_CONSUMER`,
      403,
      "denied_unknown_namespace",
    );
  }

  // 4. Resolve lineage according to consumer mode. Per-session
  //    consumers fetch pod annotations; pod-stable consumers use the
  //    configured stableId and skip the API call entirely (the pod is
  //    a shared service, not a per-user proxy).
  let lineage: PodLineage;
  if (consumer.mode === "pod-stable") {
    const synthetic = buildServiceEmail(consumer.slug, consumer.stableId);
    lineage = { sessionId: consumer.stableId, ownerEmail: synthetic };
  } else {
    try {
      lineage = await readPodLineage(verified.namespace, verified.pod.name);
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes("missing annotation")) {
        throw new ExchangeError(msg, 400, "denied_annotation_missing");
      }
      throw new ExchangeError(`pod lookup failed: ${msg}`, 502, "denied_pod_lookup_failed");
    }
  }

  // 5. Build synthetic identity.
  const email = buildServiceEmail(consumer.slug, lineage.sessionId);
  const name = buildServiceName(consumer.slug, lineage.sessionId);
  const userId = serviceUserId(consumer.slug, lineage.sessionId);

  // 5a. On-behalf-of override. Elevated consumers (allowActorOverride)
  // may supply a caller-chosen actor_email; the synthetic identity
  // (sub/email/name) is unchanged so the audit trail still says
  // "this token was minted for the orchestrator," with the human
  // named in `actor_email`. Non-elevated consumers that try to set
  // this field fail loudly: it's a privilege escalation attempt
  // (intentional or otherwise) and silent ignore would be worse.
  let actorEmail = lineage.ownerEmail;
  const requestedActorEmail = (options.requestedActorEmail ?? "").trim();
  if (requestedActorEmail !== "") {
    const allowOverride =
      consumer.mode === "pod-stable" && consumer.allowActorOverride === true;
    if (!allowOverride) {
      throw new ExchangeError(
        `consumer ${consumer.slug} may not request actor_email override`,
        403,
        "denied_actor_override_not_allowed",
      );
    }
    if (!isPlausibleActorEmail(requestedActorEmail)) {
      throw new ExchangeError(
        `actor_email ${JSON.stringify(requestedActorEmail)} failed format validation`,
        400,
        "denied_actor_email_invalid",
      );
    }
    actorEmail = requestedActorEmail.toLowerCase();
  }

  // 6. Idempotent upsert. Sessions reconnect frequently; each exchange
  //    refreshes updatedAt (visible in the admin console) but does not
  //    churn the row id. The row's email/name/role are re-set on every
  //    call so a code-level rename of any synthetic format takes effect
  //    on the next exchange.
  try {
    await upsertServiceUser({ userId, email, name });
  } catch (e) {
    throw new ExchangeError(
      `service user upsert failed: ${(e as Error).message}`,
      500,
      "error_internal",
    );
  }

  // 7. Mint. The shared helper stamps every claim the verifier
  //    contract requires (exp, iat, role, and — for service tokens —
  //    actor_email). `iss` and `aud` are filled by Better Auth's
  //    signJWT from baseURL. The `apps` claim is empty for service
  //    principals; per-app prefs are a human concept.
  let signed;
  try {
    signed = await mintAuthJwt({
      sub: userId,
      email,
      name,
      role: ROLE,
      apps: {},
      actorEmail,
    });
  } catch (e) {
    throw new ExchangeError(
      `mintAuthJwt failed: ${(e as Error).message}`,
      500,
      "error_jwt_mint",
    );
  }

  return {
    token: signed.token,
    userId,
    email,
    actorEmail,
    sessionId: lineage.sessionId,
    expiresAt: signed.exp,
  };
}

async function upsertServiceUser(opts: {
  userId: string;
  email: string;
  name: string;
}): Promise<void> {
  const now = new Date();
  // Two-step rather than ON CONFLICT to keep the Drizzle query readable
  // and to keep the existing admin-console UPDATE semantics: the
  // exchange is idempotent at the application level. Race risk is
  // negligible — the only writer to `svc:<consumer>:<sessionId>` rows
  // is this function, and concurrent exchanges for the same sessionId
  // both observe the same target state.
  const existing = await db
    .select({ id: user.id })
    .from(user)
    .where(eq(user.id, opts.userId))
    .limit(1);
  if (existing.length === 0) {
    await db.insert(user).values({
      id: opts.userId,
      email: opts.email,
      name: opts.name,
      role: ROLE,
      emailVerified: true,
      apps: "{}",
      createdAt: now,
      updatedAt: now,
    });
  } else {
    await db
      .update(user)
      .set({
        email: opts.email,
        name: opts.name,
        role: ROLE,
        emailVerified: true,
        updatedAt: now,
      })
      .where(eq(user.id, opts.userId));
  }
}
