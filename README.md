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
- `GET  /metrics` — Prometheus scrape (PodMonitor in `k8s/templates/podmonitor.yaml`); exports `auth_romaine_exchange_total{result}`, `auth_admin_origins_requests_total{method, result}`, plus prom-client Node/process/GC defaults (prefixed `auth_`). See `src/metrics.ts`.
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
per `K8S_SERVICE_SA_ALLOWLIST`). The handler reads the bound pod's
`tank-operator/owner-email` and `tank-operator/session-id` annotations at
exchange time — cross-namespace `pods/get` RBAC for each consumer namespace
is scaffolded from `k8sOidc.serviceConsumerNamespaces` in `k8s/values.yaml`.

Service-principal users are stored in Better Auth's user table under a
reserved synthetic email (`pod-<session-id>@service.<consumer>.romaine.life`)
that no human IdP can squat — the `databaseHooks.user.create.before` guard
in `src/auth.ts` refuses any IdP-sourced user-create whose email is in a
reserved domain. The issued JWT carries an extra `actor_email` claim with
the human owner so downstream services can audit and scope per-owner.

See [nelsong6/tank-operator#486](https://github.com/nelsong6/tank-operator/issues/486)
for the cross-repo architecture and rollout plan.

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
