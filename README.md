# auth

Central auth service for `*.romaine.life`. Apps redirect users here to sign in
with Microsoft / Google, then verify the issued JWTs against this service's
JWKS endpoint. Replaces the per-app `microsoft-routes.js` + shared
`api-jwt-signing-secret` pattern that previously lived in kill-me, plant-agent,
investing, house-hunt, and fzt-frontend.

## Machine authentication

Machine authentication uses a distinct `role=service, purpose=machine` account per
registered machine, with a 15-minute first-party token. The human who enrolls its
public key is the sponsor, not the identity the machine later presents. Machine
accounts cannot become browser sessions or human accounts; their grants live on
their own account's `apps` object. `apps.fzt.owner_sub` grants writes to that owner's
menu and bookmark trees, and `apps.ssh` is an explicit array of `{target,user}`.

The Go `client` package and CI-released `romaine-auth` executable share the Windows
TPM key, macOS Keychain or Linux KWallet/Secret Service credential. There is no
plaintext key fallback. `user-login` stores personal credentials in `user-token.json`;
machine refresh uses `machine-token.json`. Neither reads the old mixed
`auth-token.json`, and machine renewal never updates a human credential.

```
romaine-auth enroll nelson-laptop
romaine-auth whoami
romaine-auth user-login
romaine-auth whoami --human
romaine-auth ssh --user nelson nelsonpc hostname
romaine-auth op get /api/v3/users/me
romaine-auth home-token --role shows --out FILE
```

`home-token` (`client.HomeToken`) gets a five-minute token OpenBao signs for a home service, with no call to this service, and reuses it from `home-token-<role>.json` beside `machine-token.json` until a minute before it expires; `IsHomeDevice` recognizes one, and its `device` claim names the machine, because its `sub` is an OpenBao entity UUID.

Enrollment uses a recent browser sign-in only to authorize the public-key registration.
Re-enrollment changes the key registration while keeping the machine account stable.
`grant MACHINE-SUBJECT APPS-JSON-FILE` needs a recent personal administrator sign-in.
An administrator installs host trust with `ssh-host --user USER --principals FILE`;
the principals are target-qualified machine identities, one per line, as returned
by the SSH exchange. The command checks the SSH configuration before replacing it,
keeps the prior configuration, and reloads the host's SSH listener.
`ssh-host --user USER --principals FILE --check` changes nothing: it prints `current`
when the installed CA key, principals and SSH configuration match, otherwise one line
per part that differs.
`ssh-host --installed` changes nothing: it prints each OS login with installed
principals, or `none`. `ssh-host --user USER --remove` deletes that login's
principals; removing the last login's also removes the CA key and the SSH
configuration block, checked and reloaded the same way.
On macOS and Linux, `ssh-host --user USER --principals FILE --user-scope` instead
installs the CA and exact principal list in the current account's `authorized_keys`.
This needs no administrator access or listener restart and preserves existing keys.
OS logins containing `@`, such as a macOS directory account, are accepted literally.

`POST /api/auth/device/token` requires an explicit audience: `machine` for first-party credentials, or `audience=ssh` with `public_key`, `target` and
`user`, returning a certificate lasting at most ten minutes. `audience=openproject`
exchanges the machine proof for an OpenProject-native OAuth token lasting at most
two hours. Both require `request_hash`, the hexadecimal SHA-256 of sorted-key JSON
containing the request fields other than `assertion`. OpenProject confidential-client
credentials are mapped by machine subject in `ng6-auth/openproject-machine-clients`,
synced to `OPENPROJECT_MACHINE_CLIENTS`; the machine receives only the expiring token.
Provision these with at-home-tools' `op-machine`, which creates a distinct OpenProject
administrator account per machine (Nelson's current permission choice).

The machine client no longer uses `audience=openproject` (OPADMIN-23): a home PC reads
its own OpenProject client from OpenBao (`secret/devices/<device>/openproject`, nelsong6/openbao)
with its device login and signs in to OpenProject itself, so OpenProject can answer at
home only. The server's exchange is removed once OpenProject has left the internet.

Revocation stops new exchanges. Already-issued credentials expire naturally: fifteen
minutes for first-party machine tokens, ten for SSH certificates, and two hours for
OpenProject. Old clients omitting the audience are refused so they cannot select machine subjects as personal trees. Legacy device-as-human tokens must be
discarded by clients; fzt rejects them. Other existing JWT verifiers may accept such
tokens until their original 24-hour expiry.

## Stack

- **Hono** on Node 20 (Web Standards request/response, portable to Bun / edge if we want it)
- **Better Auth** for the OAuth/OIDC flow, session storage, custom user fields, and JWT issuance
- **Drizzle** (postgres-js driver) against a **CloudNativePG** Postgres cluster running in this app's namespace
- All secrets injected via env: DB creds come from CNPG's auto-managed `auth-db-app` Secret; OAuth client secrets and `BETTER_AUTH_SECRET` arrive via an ExternalSecret synced from the auth-owned `ng6-auth` Key Vault. The pod itself has no direct Azure dependencies

## Endpoints

- `POST /api/auth/sign-in/social/microsoft` — kicks off the Entra ID flow
- `POST /api/auth/sign-in/social/google` — kicks off the Google flow
- `GET  /api/auth/get-session` — returns the current session for the cookie
- `GET  /api/auth/jwks` — JSON Web Key Set; **apps verify issued JWTs against this URL**
- `GET  /api/admin/origins[/{project}]` — list glimmung-managed slot wildcards (k8s-SA-auth)
- `PUT  /api/admin/origins/{project}` — replace a project's slot wildcards (k8s-SA-auth, idempotent)
- `DELETE /api/admin/origins/{project}` — drop a project's slot wildcards (k8s-SA-auth)
- `POST /api/auth/exchange/k8s` — exchange a session-pod's projected SA token for an auth.romaine.life `role=service` JWT
- `POST /api/auth/exchange/federation` — exchange a workload's projected SA token for an external-audience JWT (RFC 7523 client_assertion; today: Tailscale). Distinct allowlist + output shape from the `/k8s` path
- `POST /api/auth/exchange/ssh-cert` — exchange an issuance gateway's projected SA token for a short-lived OpenSSH **user certificate** (auth owns the SSH CA key). Distinct signing key class (ed25519 SSH CA, not the JWKS key), distinct allowlist (`K8S_SSH_CERT_SA_ALLOWLIST`). See "SSH certificate issuance" below
- `GET  /api/ssh/ca` — the SSH CA **public** key as a `TrustedUserCAKeys` line (unauthenticated; a CA public key is published-by-design). 404 when the CA is unconfigured
- `POST /admin/bot-tokens` — admin-only: mint a 24h bot token (`role=admin`, `purpose=bot`) for break-glass CLI / curl use
- `POST /admin/service-tokens` — admin-only: mint a 24h service token (`role=service`, `purpose=bot`, `actor_email=<admin>`) for calling service-only MCPs (e.g. `mcp-github`) from a workstation
- `POST /admin/test-slot-model-approvals/grants` — admin-only: approve a Tank test-slot session to use a model or reasoning effort above the low-cost baseline from an `intent=test-slot-model` approval URL. Production sessions are not eligible for this approval path
- `POST /api/cli/device` + `POST /api/cli/token` — browser-approved CLI/device flow for minting the same 24h bot token without copying an auth cookie
- `GET /api/auth/cli/user-login` + `POST /api/auth/cli/user-token` — native-desktop sign-in flow (RFC 8252, PKCE + loopback). The user signs in normally with Microsoft/Google in the browser; a native app on the same machine receives the user's own JWT (`role=user|admin`, no `purpose=bot`) via a one-time code redeemed at the token endpoint. No admin approval — the user IS the requester. First consumer: `romaine-life/shows`'s `desktop/`.
- `GET  /metrics` — Prometheus scrape (PodMonitor in `k8s/templates/podmonitor.yaml`); exports `auth_romaine_exchange_total{result}`, `auth_admin_origins_requests_total{method, result}`, `auth_admin_bot_tokens_minted_total`, `auth_admin_service_tokens_minted_total`, `auth_admin_test_slot_model_approvals_total`, `auth_federation_exchange_total{result}`, `auth_ssh_cert_exchange_total{result}`, plus prom-client Node/process/GC defaults (prefixed `auth_`). See `src/metrics.ts`.
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

See [romaine-life/glimmung#142](https://glimmung.romaine.life/i/glimmung/142) for
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
Tank-operator native test-slot session pods are allowlisted as
`tank-operator-slot-N-sessions/tank-operator-slot-N-session` and route through
the per-session `tank` consumer with slot-prefixed synthetic ids. That keeps
`/api/auth/exchange/k8s` testable for both repo discovery and repo cloning
without collapsing slot audit rows into prod identities.

Service-principal users are stored in Better Auth's user table under a
reserved synthetic email (`pod-<session-id>@service.<consumer>.romaine.life`)
that no human IdP can squat — the `databaseHooks.user.create.before` guard
in `src/auth.ts` refuses any IdP-sourced user-create whose email is in a
reserved domain. The issued JWT carries an extra `actor_email` claim with
the human owner so downstream services can audit and scope per-owner.

See [romaine-life/tank-operator#486](https://github.com/romaine-life/tank-operator/issues/486)
for the cross-repo architecture and rollout plan.

## SSH certificate issuance

auth owns the SSH certificate authority for romaine.life-managed remote-host
execution. It holds the **only** SSH CA private key and is the **only** issuer
of OpenSSH user certificates. This replaces glimmung's retired local signer
(`glimmung/internal/server/ssh_ca.go` + the `glimmung-ssh-ca-private-key` KV
secret + `GLIMMUNG_SSH_CA_PRIVATE_KEY` env, all deleted in the glimmung-side
PR of this migration). The trust root for SSH on a managed host is now the
identity provider, not the workflow orchestrator.

Flow: a per-run issuance gateway (today: glimmung's native-runner ssh-cert
callback, which validates the run token and derives the run-scoped `key_id`
`glimmung-run:<project>/<run_id>` and principal `<project>-agent`) presents
its projected k8s SA token plus a freshly minted ed25519 public key to
`POST /api/auth/exchange/ssh-cert`. auth validates and **clamps every
security-relevant field server-side** before the CA key signs anything:

- principals must match `SSH_CERT_PRINCIPAL_PATTERN` (default
  `^[a-z0-9][a-z0-9-]{0,62}-agent$` — a caller cannot request `root` or an
  arbitrary login), capped at 4;
- extensions are restricted to `permit-pty` (no port/agent/X11 forwarding, no
  user-rc); critical options are never honored from the caller;
- TTL is bounded `[60s, 1h]` (default 10m) and **rejected, never silently
  clamped**, when out of range;
- the public key must be `ssh-ed25519` and must not itself be a certificate.

Inbound bearer is the gateway's projected SA token (RS256, audience pinned to
`https://auth.romaine.life` per `K8S_SSH_CERT_AUDIENCE`, namespace+SA pinned
per `K8S_SSH_CERT_SA_ALLOWLIST`). That allowlist is deliberately **narrower**
than the service/federation allowlists — minting a host login credential is a
higher-trust action than minting a service or federation JWT — so only the
issuance gateway (`glimmung/infra-shared`) lands there.

The signing primitive (`src/ssh-cert.ts`) is a hand-rolled OpenSSH
`PROTOCOL.certkeys` encoder over Node's stdlib ed25519 `crypto.sign` — no
third-party SSH crypto dependency enters the identity provider's trust
boundary. The contract test (`src/ssh-cert.test.ts`) proves the cert decodes
to the requested structure, the signature verifies under the CA public key,
and (in CI, with openssh-client installed) that real `ssh-keygen -L` parses it
and reports the same principal / key id / validity / extension.

The CA **private** key is the `auth-ssh-ca-private-key` KV secret (PKCS#8 PEM
ed25519), synced into env `SSH_CA_PRIVATE_KEY` via the ExternalSecret. An unset
key fails issuance closed (503) and returns 404 from `GET /api/ssh/ca` rather
than serving an empty trust anchor. The CA **public** key is served at
`GET /api/ssh/ca` for hosts to populate `TrustedUserCAKeys`. See
`k8s/values.yaml` (`k8sOidc.sshCert*`) for the one-time key-provisioning steps.

`auth_ssh_cert_exchange_total{result}` counts issuances by outcome; per-mint
identity (subject, key id, principals, expiry) is in a structured
`[ssh-cert] issued` audit log line, not a metric label (cardinality
discipline). A sustained `error_ca_unconfigured` means issuance is down even
while sign-in and the JWT exchanges are healthy.

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
[`romaine-life/mcp-github`](https://github.com/romaine-life/mcp-github), whose
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

## Tank app approvals

Tank-owned operational break-glass grants, including Git and Azure session
grants, live in `romaine-life/tank-operator`. auth only keeps the narrow admin
approval surface for test-slot model/effort elevation: auth authenticates the
admin, mints a short-lived service JWT server-side, calls Tank's slot grant
endpoint, and returns only the grant status to the browser.

## CLI-approved bot-token flow

`/api/cli/device` is the safer CLI path for agents like Codex. The local client
creates a pending request, opens the browser approval page, and receives the
same `role=admin`, `purpose=bot` JWT that `/admin/bot-tokens` mints after the
signed-in admin approves.

Fetch requester guidance before choosing approval-page fields:

```sh
curl -sS https://auth.romaine.life/api/cli/requester-guidance
```

Response:

```json
{
  "instructions": "Choose requester fields before calling POST /api/cli/device...",
  "fields": {
    "where_happening": "Describe where this request is happening...",
    "intended_use": "Describe what the bot token will be used for...",
    "misc_identifier": "Choose one common concrete singular noun..."
  },
  "constraints": {
    "where_happening_max_length": 500,
    "intended_use_max_length": 500,
    "misc_identifier_max_length": 80,
    "previous_misc_identifiers_limit": 50
  },
  "supported_approval_inputs": {
    "environment_name": {
      "label": "Environment name",
      "description": "Choose the non-secret DNS-safe name...",
      "placeholder": "loading-feature",
      "max_length": 63
    }
  },
  "previous_misc_identifiers": ["lantern", "teapot"]
}
```

Start a request:

```sh
curl -sS -X POST https://auth.romaine.life/api/cli/device \
  -H 'Content-Type: application/json' \
  -d '{
    "where_happening": "Codex desktop session in D:\\repos\\auth",
    "intended_use": "Use auth.romaine.life bot-token auth for follow-on romaine API calls requested in this session",
    "misc_identifier": "anvil",
    "approval_inputs": ["environment_name"],
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

`where_happening`, `intended_use`, and `misc_identifier` are required and
intentionally loose. Agent callers should describe where the request is coming
from, what the token is intended for, and provide a noun-style misc identifier
that is not listed in `previous_misc_identifiers`. The approval page shows all
three fields before the admin approves.

`approval_inputs` is optional. Each requested name must appear in
`supported_approval_inputs`; unknown and duplicate names are rejected. Auth
owns the label, help text, normalization, and validation so an untrusted
requester cannot turn the approval page into an arbitrary data-entry form.
Requested values are explicitly non-secret and the approval page warns that
they are returned to the requesting CLI.

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

The token response extends `/admin/bot-tokens` with the approved values:
`{ token, expires_at, expires_in_hours, purpose, approval_values }`. A request
for `environment_name` returns, for example,
`"approval_values": { "environment_name": "loading-feature" }`. These values
are grant metadata, not JWT claims. Request secrets and one-time codes are
stored only as SHA-256 hashes in Postgres. Loopback redirects are limited to
explicit-port `http://localhost`, `http://127.0.0.1`, or `http://[::1]`, and
loopback use requires `code_challenge_method=S256`.

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
Apps on another registrable domain use this service's OIDC authorization-code
flow instead. `chess-tactics.com` is a public PKCE client whose backend performs
the exchange and maintains host-only application cookies.

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

ArgoCD renders the Helm chart in [k8s/](k8s/) (Application manifest lives in
`infra-bootstrap/k8s/apps/auth.yaml`). The pipeline is:

1. After server inputs change on `main`, [CI](.forgejo/workflows/ci.yaml) validates, builds and pushes the image to `romainecr`, then opens a checked PR updating `k8s/values.yaml`.
2. After that image pin merges, ArgoCD rolls the Deployment. Client-only changes release the native clients without rebuilding the server image.
3. CNPG manages the Postgres cluster lifecycle alongside

Cluster credentials come from CNPG's auto-generated `auth-db-app` Secret;
OAuth client secrets and `BETTER_AUTH_SECRET` come from the auth-owned
`ng6-auth` Key Vault via an ExternalSecret in
[k8s/externalsecret.yaml](k8s/externalsecret.yaml).

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
