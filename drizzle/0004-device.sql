-- Home devices (src/device-helpers.ts, ROMAINE-46, BAO-2): a machine a signed-in user
-- registered once, by the public half of a key it can't export. Expand only: nothing reads
-- this table until the image that adds /api/auth/device/* is rolled, so apply it first.
CREATE TABLE IF NOT EXISTS "device" (
  "id" text PRIMARY KEY,
  "user_id" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "name" text NOT NULL,
  "public_key_jwk" jsonb NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT now(),
  "last_used_at" timestamp,
  "revoked_at" timestamp
);
-- One live registration per user and name; revoked rows stay for the audit trail.
CREATE UNIQUE INDEX IF NOT EXISTS "device_user_name_live" ON "device" ("user_id", "name") WHERE "revoked_at" IS NULL;
-- Applied by hand as postgres; the app connects as `auth`, which owns every other table.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth') THEN
    ALTER TABLE "device" OWNER TO auth;
  END IF;
END $$;
