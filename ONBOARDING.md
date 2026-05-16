# Onboarding auth.romaine.life under glimmung

One-time bootstrap to register `auth` as a glimmung-managed project and
stand up the wildcard ingress that its test slots attach to.

## What test slots are for

Each slot is a running copy of the auth app at
`auth-slot-N.auth.dev.romaine.life`, started with `TEST_MODE=true`. The
server renders the redesigned UI against hardcoded fixture data (Rachael
Tyrell + a handful of accounts/sessions/users); sign-in just sets a cookie,
sign-out clears it. There is **no** dev database, **no** dev OAuth client,
**no** real authentication happening. Slots exist so an operator can cruise
the signed-out, signed-in, and admin views in isolation.

## Prerequisites

The prod chart adds a wildcard cert (`auth-wildcard-tls`) and XListenerSet
(`auth-wildcard`) covering `auth.dev.romaine.life` and
`*.auth.dev.romaine.life`. The cert uses `letsencrypt-prod-dns01` because
HTTP-01 cannot issue wildcards; ensure that ClusterIssuer exists before
reconciling. Toggle the whole dev surface off with
`wildcardCertificate.enabled: false` in [k8s/values.yaml](k8s/values.yaml).

## Register the project with glimmung

```bash
GLIMMUNG=https://glimmung.romaine.life
TOKEN=$(az account get-access-token --resource <glimmung-entra-client-id> --query accessToken -o tsv)

curl -fsSL -X POST "$GLIMMUNG/v1/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "name": "auth",
  "github_repo": "nelsong6/auth",
  "metadata": {
    "native_webapp": true,
    "native_standby_dns": {
      "enabled": true,
      "record_base": "auth.dev.romaine.life",
      "slot_prefix": "auth-slot",
      "count": 0
    }
  }
}
JSON
```

Notes:

- `count: 0` registers the project without provisioning slots. Bump it via
  the patch call below once the wildcard cert is live and you're ready to
  cruise.
- `native_auth_redirects` is **not** part of the metadata. Test slots run
  in `TEST_MODE` and never touch Microsoft, so there's no Entra app reg to
  reconcile redirect URIs against. (When the all-via-auth.romaine.life
  migration is done, downstream apps drop their own Entra reg anyway and
  this stays unused for them too.)

## Provision slots

```bash
curl -fsSL -X PATCH "$GLIMMUNG/v1/projects/auth/test-environments/count" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"count": 3}'
```

Glimmung's reconciler installs three releases of [k8s/issue/](k8s/issue/)
in the `auth` namespace:

```bash
helm install auth-slot-1 ./k8s/issue \
  --namespace auth \
  --set image.tag=<sha> \
  --set hostname=auth-slot-1.auth.dev.romaine.life
```

Each slot's deployment sets `TEST_MODE=true`, a fake `BASE_URL`, and a
`COOKIE_DOMAIN` of `auth.dev.romaine.life`. No DB or OAuth credentials are
mounted.

## Verify

After a slot reports `usable: true`:

- `https://auth-slot-1.auth.dev.romaine.life/` — signed-out card, rotating
  empathy prompt, MS + Google buttons (both wired to the test cookie path).
- Click **Sign in with Microsoft** → cookie set, redirect to `/` → signed-in
  dashboard renders with Rachael Tyrell as the test user, role=admin, four
  granted apps in the modules grid.
- The **Tyrell Console** button → `/admin` → fixture user list (Rachael,
  Deckard, J.F. Sebastian). Form submissions redirect back with a
  `test mode · changes are discarded` flash.
- Click **End interview** → cookie cleared, back to signed-out card.
- Confirm the cookie's `Domain` attribute is `auth.dev.romaine.life`, not
  `romaine.life`.

## Tearing down

- A single slot: `helm uninstall auth-slot-N -n auth`.
- All slots: `PATCH /v1/projects/auth/test-environments/count` with `count: 0`.
- The whole dev surface: set `wildcardCertificate.enabled: false` in
  [k8s/values.yaml](k8s/values.yaml) and sync the prod chart.

## When real-auth slots become a thing

If you ever want a slot that does real sign-in (e.g. to validate a Better
Auth upgrade end-to-end against Microsoft), that requires a separate dev
Entra app reg with pre-registered `auth-slot-N.../api/auth/callback/microsoft`
redirect URIs, plus a dev CNPG cluster with the Better Auth schema pushed.
Out of scope for the design-cruising use case.
