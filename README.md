# auth

Central auth service for `*.romaine.life`. Apps redirect users here to sign in
with Microsoft / Google, then verify the issued JWTs against this service's
JWKS endpoint. Replaces the per-app `microsoft-routes.js` + shared
`api-jwt-signing-secret` pattern that previously lived in kill-me, plant-agent,
investing, house-hunt, and fzt-frontend.

## Stack

- **Hono** on Node 20 (Web Standards request/response, portable to Bun / edge if we want it)
- **Better Auth** for the OAuth/OIDC flow, session storage, custom user fields, and JWT issuance
- **Drizzle** (postgres-js driver) against a **CloudNativePG** Postgres cluster running in this app's namespace
- All secrets injected via env: DB creds come from CNPG's auto-managed `auth-db-app` Secret; OAuth client secrets and `BETTER_AUTH_SECRET` arrive via an ExternalSecret synced from `romaine-kv`. The pod itself has no direct Azure dependencies

## Endpoints

- `POST /api/auth/sign-in/social/microsoft` — kicks off the Entra ID flow
- `POST /api/auth/sign-in/social/google` — kicks off the Google flow
- `GET  /api/auth/get-session` — returns the current session for the cookie
- `GET  /api/auth/jwks` — JSON Web Key Set; **apps verify issued JWTs against this URL**
- `GET  /api/admin/origins[/{project}]` — list glimmung-managed slot wildcards (k8s-SA-auth)
- `PUT  /api/admin/origins/{project}` — replace a project's slot wildcards (k8s-SA-auth, idempotent)
- `DELETE /api/admin/origins/{project}` — drop a project's slot wildcards (k8s-SA-auth)
- `POST /api/auth/exchange/k8s` — exchange a session-pod's projected SA token for an auth.romaine.life `role=service` JWT
- `POST /admin/bot-tokens` — admin-only: mint a 24h bot token (`role=admin`, `purpose=bot`) for break-glass CLI / curl use
- `POST /admin/service-tokens` — admin-only: mint a 24h service token (`role=service`, `purpose=bot`, `actor_email=<admin>`) for calling service-only MCPs (e.g. `mcp-github`) from a workstation
- `POST /api/cli/device` + `POST /api/cli/token` — browser-approved CLI/device flow for minting the same 24h bot token without copying an auth cookie
- `GET  /metrics` — Prometheus scrape (PodMonitor in `k8s/templates/podmonitor.yaml`); exports `auth_romaine_exchange_total{result}`, `auth_admin_origins_requests_total{method, result}`, `auth_admin_bot_tokens_minted_total`, `auth_admin_service_tokens_minted_total`, plus prom-client Node/process/GC defaults (prefixed `auth_`). See `src/metrics.ts`.
- `GET  /health` — liveness probe
- `GET  /ready` — readiness probe

## Managed slot origins

Per-project slot wildcards (e.g. `https://*.tank.dev.romaine.life`) live in
the `managed_origin` table, **owned by glimmung's reconciler**. Each row
contributes to both Better Auth's `trustedOrigins` (callbackURL validation)
and Hono's CORS allowlist on `/api/auth/*`. Static peers (the apps in
`PROD_TRUSTED_ORIGINS` / `CROSS_APP_ORIGINS`) stay in source; slot wildcards
do not.

Writes to `/api/admin/origins/*` authenticate via the inbound caller's k8s
ServiceAccount token — an RS256 JWT signed by the cluster's OIDC issuer.
Validation pins issuer, audience (`https://auth.romaine.life`), and the
`(namespace, serviceAccount)` claim against `K8S_ADMIN_SA_ALLOWLIST`.
Glimmung's deployment mounts a projected token with the right audience so
a stolen token cannot be replayed against another JWT verifier.

See [nelsong6/glimmung#142](https://glimmung.romaine.life/i/glimmung/142) for
the cross-repo architecture.

## Service-principal exchange

Kubernetes session pods (today: tank-operator) authenticate to this service
via `POST /api/auth/exchange/k8s` and receive a normal auth.romaine.life JWT
with `role=service`. Apps that opt in accept service callers by extending
their role gate to include `service`; the JWT is otherwise identical in shape
to a human JWT (same `iss`, same JWKS, same verifier) so an app that ignores
service callers needs no code changes.

Inbound bearer is the pod's projected SA token (RS256, audience pinned to
`https://auth.romaine.life` per `K8S_SERVICE_AUDIENCE`, namespace+SA pinned
per `K8S_SERVICE_SA_ALLOWLIST`). Per-session consumers read the bound pod's
`tank-operator/owner-email` and `tank-operator/session-id` annotations at
exchange time; pod-stable consumers use a configured stable service identity.
Cross-namespace `pods/get` RBAC for annotation-reading consumer namespaces is
scaffolded from `k8sOidc.serviceConsumerNamespaces` in `k8s/values.yaml`.

Tank-operator native test-slot orchestrators are allowlisted as
`tank-operator-slot-N/tank-operator-slot-N` and route through the same elevated
`tank-operator` consumer as prod, with slot-specific synthetic service users.
That keeps `/api/auth/exchange/k8s` testable for on-behalf-of repo discovery
without collapsing slot audit rows into the prod orchestrator identity.

Service-principal users are stored in Better Auth's user table under a
reserved synthetic email (`pod-<session-id>@service.<consumer>.romaine.life`)
that no human IdP can squat — the `databaseHooks.user.create.before` guard
in `src/auth.ts` refuses any IdP-sourced user-create whose email is in a
reserved domain. The issued JWT carries an extra `actor_email` claim with
the human owner so downstream services can audit and scope per-owner.

See [nelsong6/tank-operator#486](https://github.com/nelsong6/tank-operator/issues/486)
for the cross-repo architecture and rollout plan.

## Admin bot tokens (break-glass CLI auth)

`POST /admin/bot-tokens` is the break-glass path for an admin who needs a
JWT they can paste into `Authorization: Bearer …` from outside a browser —
typically to salvage state when one of the apps (tank-operator's chat UI,
glimmung's pane, etc.) is broken and the normal browser flow is unusable.

Flow:

1. Sign in to `https://auth.romaine.life/admin` (admin only — the page itself
   rejects non-admin callers).
2. Click **Mint bot token**. The page POSTs to `/admin/bot-tokens`, displays
   the resulting JWT once with a copy-to-clipboard button, and forgets it
   client-side after navigation.
3. Paste into an environment variable and curl: `curl -H "Authorization:
   Bearer $TANK_JWT" https://tank.romaine.life/api/sessions/8/events`.

JWT shape: standard auth.romaine.life claims (`sub`, `email`, `name`,
`role=admin`, `apps`) plus a `purpose: "bot"` custom claim so downstream
audit logs can distinguish bot mints from browser sign-ins. TTL is **24
hours** — long enough for an unhurried debugging session, short enough that
a token leaked into a shell history file is recovered automatically.

**Revocation before natural expiry.** No per-token revocation table —
`az keyvault key rotate auth-jwt-signing` invalidates every outstanding
auth.romaine.life JWT (cookie tokens, exchanged tokens, bot tokens) by
rolling the signing key. This is the right tool for "I think a bot token
leaked" since the bot-token surface is rare-event by design; rolling has no
steady-state cost.

Observability: `auth_admin_bot_tokens_minted_total` (Prometheus, label-free —
the per-mint identity is captured by a `console.warn` line that includes the
admin's email, so structured-log search is the audit path).

## Admin service tokens (CLI auth for service-only MCPs)

`POST /admin/service-tokens` is the sibling of `/admin/bot-tokens` for the
case where the downstream consumer's verifier pins on `role=service` rather
than `role=admin`. The motivating consumer is
[`nelsong6/mcp-github`](https://github.com/nelsong6/mcp-github), whose
JWT validator requires:

```
role == "service"  AND  actor_email is non-empty
```

The bot-token mint produces `role=admin` and never carries `actor_email`
(the helper in `src/mint-jwt-helpers.ts` forbids it for non-service
tokens), so an admin-minted bot token can't satisfy that contract. The
service-token mint produces `role=service` and sets
`actor_email=<admin's email>` — the admin is acting as a service
principal on their own behalf, and the audit field carries the human
responsible.

Flow is the same as bot tokens: sign in to `/admin`, click **Mint service
token**, paste the resulting JWT into `Authorization: Bearer …`. TTL is
24 hours and revocation is the same key-rotation path.

Design note: this surface intentionally does NOT route through the k8s
service-account exchange (`/api/auth/exchange/k8s`). That flow exists for
pods whose identity comes from a projected SA token and whose actor is
encoded in pod annotations — an admin at a workstation has neither, and
threading the SA-exchange's synthetic-email / pod-lineage machinery
through it would be machinery for machinery's sake. If a future use case
wants a long-lived service identity for a named admin (separate user
row, reusable `sub`, etc.), the right move is to add a
`mode: "admin-bot"` consumer to `src/service-exchange.ts` rather than
evolve this surface.

Observability: `auth_admin_service_tokens_minted_total` (Prometheus,
label-free, same posture as the bot-token counter). A separate
`console.warn` line per mint carries the admin's email and the issued
`actor_email` (equal today, kept explicit so a future decoupling
surfaces in the log diff).

## CLI-approved bot-token flow

`/api/cli/device` is the safer CLI path for agents like Codex. The local client
creates a pending request, opens the browser approval page, and receives the
same `role=admin`, `purpose=bot` JWT that `/admin/bot-tokens` mints after the
signed-in admin approves.

Start a request:

```sh
curl -sS -X POST https://auth.romaine.life/api/cli/device \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "Codex desktop",
    "redirect_uri": "http://127.0.0.1:49152/callback",
    "state": "opaque-client-state",
    "code_challenge": "<base64url-sha256-code-verifier>",
    "code_challenge_method": "S256"
  }'
```

Response:

```json
{
  "device_code": "...",
  "user_code": "VK-ABCD-1234",
  "verification_uri": "https://auth.romaine.life/cli",
  "verification_uri_complete": "https://auth.romaine.life/cli?user_code=VK-ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

The client should try to open `verification_uri_complete`. If that fails, show
`verification_uri` and `user_code` so the admin can enter the code manually.
After approval, the page displays a one-time code for paste fallback. If a
loopback `redirect_uri` was supplied, the page also shows a visible
user-clicked return link with `?code=...&state=...`. It does not automatically
contact localhost from the browser.

Poll with the device code:

```sh
curl -sS -X POST https://auth.romaine.life/api/cli/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "<device_code>"
  }'
```

Or exchange the callback/pasted one-time code with PKCE:

```sh
curl -sS -X POST https://auth.romaine.life/api/cli/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "authorization_code",
    "code": "<one-time-code>",
    "code_verifier": "<original-code-verifier>"
  }'
```

The token response matches `/admin/bot-tokens`: `{ token, expires_at,
expires_in_hours, purpose }`. Request secrets and one-time codes are stored only
as SHA-256 hashes in Postgres. Loopback redirects are limited to explicit-port
`http://localhost`, `http://127.0.0.1`, or `http://[::1]`, and loopback use
requires `code_challenge_method=S256`.

## How apps consume this

Replace the per-app `microsoft-routes.js` + shared-secret `jwt.verify()` with JWKS-based verification:

```js
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL("https://auth.romaine.life/api/auth/jwks"));

export async function requireAuth(req, res, next) {
  const token = req.cookies.auth_token ?? req.headers.authorization?.slice(7);
  if (!token) return res.status(401).end();
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: "https://auth.romaine.life",
    });
    req.user = payload; // { sub, email, name, role, apps }
    next();
  } catch {
    res.status(401).end();
  }
}
```

Frontends start sign-in via redirect:

```js
window.location.href =
  `https://auth.romaine.life/api/auth/sign-in/social/microsoft?callbackURL=${encodeURIComponent(location.origin)}`;
```

The session cookie is scoped to `.romaine.life` — SSO across every subdomain.

## Custom user attributes

`user.role` and `user.apps` (JSON string) are defined under
`additionalFields` in [src/auth.ts](src/auth.ts) and surface as columns in
[src/db/schema.ts](src/db/schema.ts). To add more, declare them in both files
and run `npx @better-auth/cli generate` to regenerate the schema, then
`npm run db:push` to apply.

Per-app data heavier than a few KV-style preferences belongs in the app's own
database keyed by `user.id`, not in `apps`.

## Local development

```sh
npm install
docker run -d --name auth-pg -p 5432:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=auth \
  postgres:17
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth
export BETTER_AUTH_SECRET=$(openssl rand -hex 32)
export MICROSOFT_CLIENT_ID=...      # see Key Vault `microsoft-oauth-client-id`
export MICROSOFT_CLIENT_SECRET=...
export GOOGLE_CLIENT_ID=...
export GOOGLE_CLIENT_SECRET=...
export BASE_URL=http://localhost:3000
npm run db:push
npm run dev
```

## Deployment

ArgoCD syncs everything in [k8s/](k8s/) (Application manifest lives in
`infra-bootstrap/k8s/apps/auth.yaml`). The pipeline is:

1. Push to `main` → [build-and-deploy](.github/workflows/build-and-deploy.yml) builds the image, pushes to `romainecr`, bumps the tag in `k8s/kustomization.yaml`, commits back
2. ArgoCD picks up the kustomization change, rolls the Deployment
3. CNPG manages the Postgres cluster lifecycle alongside

Cluster credentials come from CNPG's auto-generated `auth-db-app` Secret;
OAuth client secrets and `BETTER_AUTH_SECRET` come from `romaine-kv` via an
ExternalSecret in [k8s/externalsecret.yaml](k8s/externalsecret.yaml).

## Bootstrap dance

After the first `tofu apply` against this repo (which writes `auth-better-auth-secret` to Key Vault) and the first ArgoCD sync (which brings up the Postgres cluster and the auth pod):

1. **Once-only** — push the Drizzle schema into the empty `auth` database. `drizzle-kit` isn't shipped in the production image (devDep only), so do it from your laptop via a port-forward:
   ```sh
   kubectl -n auth port-forward svc/auth-db-rw 5432:5432 &
   export DATABASE_URL="$(kubectl -n auth get secret auth-db-app -o jsonpath='{.data.uri}' | base64 -d | sed 's/auth-db-rw\.auth\.svc\.cluster\.local/localhost/')"
   npm run db:push
   ```
   The pod will crash-loop until this is done (Better Auth queries tables that don't exist yet). Once pushed, the next pod start succeeds.
2. The tofu lockfile for this repo is created by running the `Update Tofu Lockfile` workflow once via `workflow_dispatch`. After that, the `Check Tofu Lockfile` check on PRs will pass.

## Follow-ups (separate PRs)

- **infra-bootstrap**: add `https://auth.romaine.life/api/auth/callback/microsoft` to the `azuread_application.microsoft_login` redirect URIs and drop the per-app SPA redirects
- **infra-bootstrap**: add `k8s/apps/auth.yaml` ArgoCD Application pointing at this repo
- **per-app PRs** (kill-me, plant-agent, investing, house-hunt, fzt-frontend): replace `microsoft-routes.js` + shared-secret JWT with JWKS verification; replace MSAL frontend with the redirect snippet above
