// Glimmung-managed slot origin allowlist. The store backs Better Auth's
// `trustedOrigins` resolver (in src/auth.ts) and Hono's CORS matcher on
// `/api/auth/*` (in src/server.ts). Writes come exclusively from glimmung's
// reconciler via the admin endpoints in src/server.ts; reads are per-request
// behind a short in-process cache.
//
// See nelsong6/glimmung#142 for the cross-repo architecture.

import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { db } from "./db/client.js";
import { managedOrigin } from "./db/schema.js";
import { validateWildcard } from "./wildcard.js";

// 60s in-process cache. Resolver runs per signInSocial call and per CORS
// preflight; without a cache, every Microsoft-sign-in-button click is a DB
// roundtrip. 60s is short enough that admin writes converge fast (writes
// invalidate immediately; the cache TTL is just the worst case when an admin
// write was missed somehow, e.g. another auth pod replica).
const CACHE_TTL_MS = 60_000;

interface CacheEntry {
  wildcards: string[];
  expiresAt: number;
}

let cache: CacheEntry | null = null;

export function invalidateManagedOriginsCache(): void {
  cache = null;
}

/** All managed wildcards across all projects, cached for 60s. */
export async function getManagedOrigins(): Promise<string[]> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) return cache.wildcards;
  const rows = await db
    .select({ wildcard: managedOrigin.wildcard })
    .from(managedOrigin);
  const wildcards = rows.map((r) => r.wildcard);
  cache = { wildcards, expiresAt: now + CACHE_TTL_MS };
  return wildcards;
}

export interface ManagedOriginRow {
  project: string;
  wildcard: string;
  createdAt: Date;
  updatedAt: Date;
}

export async function listManagedOrigins(): Promise<ManagedOriginRow[]> {
  return db
    .select({
      project: managedOrigin.project,
      wildcard: managedOrigin.wildcard,
      createdAt: managedOrigin.createdAt,
      updatedAt: managedOrigin.updatedAt,
    })
    .from(managedOrigin)
    .orderBy(managedOrigin.project, managedOrigin.wildcard);
}

export async function listManagedOriginsByProject(project: string): Promise<string[]> {
  const rows = await db
    .select({ wildcard: managedOrigin.wildcard })
    .from(managedOrigin)
    .where(eq(managedOrigin.project, project));
  return rows.map((r) => r.wildcard).sort();
}

/**
 * Replace the wildcard set for one project. Idempotent: same input produces
 * the same persisted state. Cache is invalidated unconditionally on success.
 *
 * Throws if any wildcard fails validation; nothing is persisted in that case.
 */
export async function replaceProjectOrigins(
  project: string,
  wildcards: string[],
): Promise<void> {
  if (!project || project.trim() !== project) {
    throw new Error("project must be a non-empty trimmed string");
  }
  const normalized = Array.from(new Set(wildcards.map((w) => w.trim()))).filter(
    (w) => w.length > 0,
  );
  for (const w of normalized) validateWildcard(w);
  const now = new Date();
  await db.transaction(async (tx) => {
    await tx.delete(managedOrigin).where(eq(managedOrigin.project, project));
    if (normalized.length > 0) {
      await tx.insert(managedOrigin).values(
        normalized.map((w) => ({
          id: randomUUID(),
          project,
          wildcard: w,
          createdAt: now,
          updatedAt: now,
        })),
      );
    }
  });
  invalidateManagedOriginsCache();
}

export async function deleteProjectOrigins(project: string): Promise<void> {
  await db.delete(managedOrigin).where(eq(managedOrigin.project, project));
  invalidateManagedOriginsCache();
}

// `validateWildcard` is exported from src/wildcard.ts so it can be tested
// in isolation (the store accessors above pull in the DB client, which
// requires DATABASE_URL at module init).
