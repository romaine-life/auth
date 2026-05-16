import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

// Test slots run with TEST_MODE=true and no real DATABASE_URL. The server
// handlers branch on TEST_MODE before any DB call, so the client below is
// never actually queried in that mode — but we still need a non-null URL
// for postgres-js to instantiate without throwing.
const TEST_MODE = process.env.TEST_MODE === "true";
const databaseUrl = process.env.DATABASE_URL;
if (!TEST_MODE && !databaseUrl) throw new Error("DATABASE_URL is required");

const queryClient = postgres(
  databaseUrl ?? "postgres://test:test@127.0.0.1:5432/test?sslmode=disable",
  { max: 10 },
);
export const db = drizzle(queryClient, { schema });
