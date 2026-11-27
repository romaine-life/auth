// Break-glass on approval (AHT-209): one Claude session, on one home machine, acts as
// cluster-admin on the home k3s cluster for a while, past owner-guard, once an administrator
// approves it.
//
// The machine files a request (POST /api/break-glass/requests, with its machine token): why,
// for how long, and which Claude session asks. An administrator approves or denies it on
// /break-glass/<id>. owner-guard asks GET /api/break-glass/active whether the session it
// guards holds a grant. While one lasts, the machine's device-token exchange with audience
// "home-cluster-break-glass" returns a short-lived JWT (iss https://auth.romaine.life, aud
// home-cluster-break-glass, claims device and grant) that the home cluster's API server
// trusts as cluster-admin (nelsong6/home-cluster). auth signs it only for a machine holding
// an approved, unexpired, unrevoked grant: the approval is the gate.
//
// It runs on Azure access's grant machinery (src/azure-access.ts): the same request rules
// (a reason, 15 to 480 minutes, 60 by default), statuses, held status requests and refusals.

import { AzureAccessError, parseAzureAccessRequest } from "./azure-access.js";

/** The audience of the cluster's break-glass token, which its API server requires. */
export const BREAK_GLASS_AUDIENCE = "home-cluster-break-glass";
/** A cluster token lives at most this long, and never past its grant. */
export const BREAK_GLASS_TOKEN_TTL_SECONDS = 10 * 60;

/** A Claude session id: a UUID today; kept to characters safe in a log line and a page. */
const SESSION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface BreakGlassRequest {
  reason: string;
  minutes: number;
  session: string;
}

/** The request a machine files: a reason, a duration in minutes, and the Claude session the
 *  grant is for. Refusals are AzureAccessError, as for every grant route. */
export function parseBreakGlassRequest(body: Record<string, unknown>): BreakGlassRequest {
  const { reason, minutes } = parseAzureAccessRequest(body);
  const session = typeof body.session === "string" ? body.session.trim() : "";
  if (!session) throw new AzureAccessError("invalid_request", 400, "session is required: the Claude session id the grant is for");
  if (!SESSION.test(session)) throw new AzureAccessError("invalid_request", 400, "session isn't a Claude session id");
  return { reason, minutes, session };
}

/** How long a cluster token minted now may live: ten minutes, or less when the grant ends
 *  sooner. Zero or less means the grant is over. */
export function breakGlassTokenTtlSeconds(grantExpiresAt: Date, now: Date): number {
  return Math.min(BREAK_GLASS_TOKEN_TTL_SECONDS, Math.floor((grantExpiresAt.getTime() - now.getTime()) / 1000));
}

/** The table, created at startup if missing, as azure_access_grant is. Rows are kept as the
 *  audit record of every request, decision and revoke. */
export const BREAK_GLASS_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS "break_glass_grant" (
  "id" text PRIMARY KEY,
  "machine_subject" text NOT NULL,
  "device_name" text NOT NULL,
  "session" text NOT NULL,
  "reason" text NOT NULL,
  "minutes" integer NOT NULL,
  "status" text NOT NULL DEFAULT 'pending',
  "created_at" timestamp NOT NULL DEFAULT now(),
  "request_expires_at" timestamp NOT NULL,
  "decided_at" timestamp,
  "decided_by_email" text,
  "grant_expires_at" timestamp,
  "revoked_at" timestamp,
  "last_token_at" timestamp,
  "token_count" integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS "break_glass_grant_machine" ON "break_glass_grant" ("machine_subject", "status");
`;
