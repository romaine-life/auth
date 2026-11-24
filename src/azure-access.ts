// Azure access on an administrator's approval (AUT-9).
//
// A home machine files a request (POST /api/azure-access/requests, with its machine token):
// why it needs Azure and for how long. An administrator approves or denies it on
// /azure-access/<id>. While an approved grant lasts, the machine's device-token exchange
// with audience "azure" returns a short-lived JWT for Azure workload identity federation:
// iss https://auth.romaine.life, aud api://AzureADTokenExchange, sub AZURE_ACCESS_SUBJECT.
// The `azure-access` user-assigned managed identity (romaine-life/infra-bootstrap
// tofu/azure-access.tf) trusts exactly that issuer and subject, so
// `az login --service-principal --federated-token` turns the JWT into Azure access as that
// identity. auth signs the subject only for a machine holding an approved, unexpired,
// unrevoked grant: the approval is the gate.
//
// This replaces tank-operator's `request_azure_break_glass` and mcp-azure-personal, which
// gave Tank sessions the same access the same way.

import { EventEmitter } from "node:events";

/** The federated credential's subject on the azure-access identity. Changing it here
 *  without changing infra-bootstrap's tofu breaks every login. */
export const AZURE_ACCESS_SUBJECT = "azure-access:approved-grant";
/** The audience Entra requires of a federated assertion. */
export const AZURE_ACCESS_AUDIENCE = "api://AzureADTokenExchange";

/** A pending request waits this long for a decision, then expires. */
export const AZURE_REQUEST_PENDING_SECONDS = 30 * 60;
/** How long a grant may last, in minutes. */
export const AZURE_GRANT_MIN_MINUTES = 15;
export const AZURE_GRANT_MAX_MINUTES = 8 * 60;
export const AZURE_GRANT_DEFAULT_MINUTES = 60;
/** A federation JWT lives at most this long; Azure trades it for an access token that lasts
 *  about an hour, after which the machine signs in again while its grant lasts. */
export const AZURE_TOKEN_TTL_SECONDS = 10 * 60;
/** The longest a status request is held open waiting for a decision. The gateway (Envoy's
 *  default route timeout, 15 s) ends a request that runs longer. */
export const AZURE_WAIT_MAX_SECONDS = 10;
export const AZURE_REASON_MAX_LENGTH = 500;

export type AzureGrantStatus = "pending" | "approved" | "denied" | "expired" | "revoked";

export interface AzureAccessRequest {
  reason: string;
  minutes: number;
}

export class AzureAccessError extends Error {
  constructor(
    readonly reason: "invalid_request" | "not_found" | "not_machine" | "no_grant" | "not_configured",
    readonly status: 400 | 401 | 403 | 404 | 503,
    message: string,
  ) {
    super(message);
  }
}

/** The request a machine files: a reason in its own words and a duration in minutes. */
export function parseAzureAccessRequest(body: Record<string, unknown>): AzureAccessRequest {
  const reason = typeof body.reason === "string" ? body.reason.replace(/\s+/g, " ").trim() : "";
  if (!reason) throw new AzureAccessError("invalid_request", 400, "reason is required: say what the access is for");
  if (reason.length > AZURE_REASON_MAX_LENGTH) {
    throw new AzureAccessError("invalid_request", 400, `reason is longer than ${AZURE_REASON_MAX_LENGTH} characters`);
  }
  let minutes = AZURE_GRANT_DEFAULT_MINUTES;
  if (body.minutes !== undefined) {
    if (typeof body.minutes !== "number" || !Number.isInteger(body.minutes)) {
      throw new AzureAccessError("invalid_request", 400, "minutes must be a whole number");
    }
    minutes = body.minutes;
  }
  if (minutes < AZURE_GRANT_MIN_MINUTES || minutes > AZURE_GRANT_MAX_MINUTES) {
    throw new AzureAccessError("invalid_request", 400,
      `minutes must be ${AZURE_GRANT_MIN_MINUTES} to ${AZURE_GRANT_MAX_MINUTES}`);
  }
  return { reason, minutes };
}

export interface AzureGrantTimes {
  status: string;
  requestExpiresAt: Date;
  grantExpiresAt: Date | null;
}

/** A row's status as of `now`: a pending request past its deadline, or an approved grant past
 *  its end, has expired whether or not the row says so yet. */
export function effectiveStatus(row: AzureGrantTimes, now: Date): AzureGrantStatus {
  if (row.status === "pending" && now >= row.requestExpiresAt) return "expired";
  if (row.status === "approved" && (!row.grantExpiresAt || now >= row.grantExpiresAt)) return "expired";
  return row.status as AzureGrantStatus;
}

/** How long a federation JWT minted now may live: ten minutes, or less when the grant ends
 *  sooner. Zero or less means the grant is over. */
export function azureTokenTtlSeconds(grantExpiresAt: Date, now: Date): number {
  return Math.min(AZURE_TOKEN_TTL_SECONDS, Math.floor((grantExpiresAt.getTime() - now.getTime()) / 1000));
}

/** A machine's identity, from the claims of a token auth signed for it. */
export function machineFromClaims(claims: Record<string, unknown>): { subject: string; device: string } {
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  const device = typeof claims.device === "string" ? claims.device : "";
  if (claims.role !== "service" || claims.purpose !== "machine" || !sub.startsWith("device:") || !device) {
    throw new AzureAccessError("not_machine", 403, "a home machine's token is required");
  }
  return { subject: sub, device };
}

/** Wakes a status request held open on a grant the moment its decision lands. auth runs one
 *  replica, so the signal stays in this process; a request held across a restart just ends
 *  and the machine asks again. */
export function createDecisionSignal() {
  const events = new EventEmitter();
  events.setMaxListeners(0);
  return {
    notify(id: string): void {
      events.emit(id);
    },
    wait(id: string, ms: number): Promise<void> {
      return new Promise((resolve) => {
        const done = () => {
          clearTimeout(timer);
          events.off(id, done);
          resolve();
        };
        const timer = setTimeout(done, ms);
        events.on(id, done);
      });
    },
  };
}

/** The table, created at startup if missing: the app connects as `auth`, which owns the
 *  database (k8s/templates/cluster.yaml), so this needs no hand-run migration. Rows are kept
 *  as the audit record of every request and decision. */
export const AZURE_ACCESS_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS "azure_access_grant" (
  "id" text PRIMARY KEY,
  "machine_subject" text NOT NULL,
  "device_name" text NOT NULL,
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
CREATE INDEX IF NOT EXISTS "azure_access_grant_machine" ON "azure_access_grant" ("machine_subject", "status");
`;
