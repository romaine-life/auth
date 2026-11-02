// drizzle/0004-device.sql against a real Postgres (PGlite): it produces exactly the
// columns the drizzle model maps, and allows one live registration per user and name.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { getTableColumns } from "drizzle-orm";
import { KyselyPGlite } from "kysely-pglite";
import { device } from "./db/schema.js";

async function boot() {
  const { client } = await KyselyPGlite.create();
  await client.exec(`CREATE TABLE "user" ("id" text PRIMARY KEY)`);
  await client.exec(readFileSync(new URL("../drizzle/0004-device.sql", import.meta.url), "utf8"));
  await client.exec(`INSERT INTO "user" VALUES ('u_1'), ('u_2')`);
  return client;
}

test("0004 creates the columns the device model maps", async () => {
  const client = await boot();
  const res = await client.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'device'`,
  );
  const live = res.rows.map((r) => r.column_name).sort();
  const model = Object.values(getTableColumns(device)).map((c) => c.name).sort();
  assert.deepEqual(live, model);
});

test("one live registration per user and name; revoked ones stay", async () => {
  const client = await boot();
  const add = (id: string, userId: string, name: string) =>
    client.query(`INSERT INTO "device" (id, user_id, name, public_key_jwk) VALUES ($1, $2, $3, '{}')`, [id, userId, name]);
  await add("d1", "u_1", "treadmill");
  await assert.rejects(add("d2", "u_1", "treadmill"));
  await add("d3", "u_2", "treadmill");
  await client.query(`UPDATE "device" SET revoked_at = now() WHERE id = 'd1'`);
  await add("d4", "u_1", "treadmill");
  const n = await client.query<{ n: number }>(`SELECT count(*)::int AS n FROM "device" WHERE user_id = 'u_1'`);
  assert.equal(n.rows[0].n, 2);
});
