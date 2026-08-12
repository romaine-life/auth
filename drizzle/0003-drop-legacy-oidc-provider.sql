-- The contract half of drizzle/0002.
--
-- 0002 moved the deprecated `oidcProvider` plugin's tables aside rather than dropping them, so a
-- rollback to the previous image would have found its data intact. That safety has been spent:
-- the new provider is deployed, all four clients are reconciled, and a real end-to-end sign-in has
-- completed against it — Microsoft login through to an authenticated token exchange, with the
-- Chess Tactics client registered confidential and its secret required.
--
-- What is being dropped:
--
--   oauth_access_token_legacy  ~123 rows of Grafana/Argo CD/ambience sessions issued by the old
--                              plugin. They were already dead at cutover: the tokens are opaque
--                              strings the new plugin has never heard of, so nobody has been able
--                              to use one since 0002 ran. Dropping the table changes nothing a
--                              user can observe.
--   oauth_consent_legacy       empty; every first-party client skips consent.
--   oauth_application          empty; the old plugin's client table, superseded by oauth_client.
--                              It kept its own name through 0002 because nothing collided with it.
--
-- Forward-only from here. Rolling back to the pre-0002 image after this point means restoring from
-- a database backup, not renaming tables back.
--
-- Against the CNPG PRIMARY, which is not always auth-db-1 — check first, because a write to a
-- replica fails:
--
--   kubectl get pods -n auth -l cnpg.io/cluster=auth-db -L role
--   kubectl exec -n auth -i auth-db-<primary> -c postgres -- \
--     psql -U postgres -d auth -v ON_ERROR_STOP=1 < drizzle/0003-drop-legacy-oidc-provider.sql
--
-- Idempotent on re-apply.

BEGIN;

DROP TABLE IF EXISTS "oauth_access_token_legacy";
DROP TABLE IF EXISTS "oauth_consent_legacy";
DROP TABLE IF EXISTS "oauth_application";

COMMIT;
