import { createHash } from "node:crypto";
import type { AuthJwtInput } from "./mint-jwt-helpers.js";
import { DeviceError, deviceSubject } from "./device-helpers.js";

export function machineIdentity(ownerId: string, name: string) {
  const id = deviceSubject(ownerId, name);
  const email = `${createHash("sha256").update(id).digest("hex")}@service.machine.romaine.life`;
  return { id, email, name: `Machine: ${name}` };
}

export function machineTokenInput(ownerId: string, name: string, apps: Record<string, unknown>): AuthJwtInput {
  const identity = machineIdentity(ownerId, name);
  return {
    sub: identity.id, email: identity.email, name: identity.name,
    role: "service", actorEmail: identity.email, purpose: "machine", device: name,
    apps, ttlSeconds: 15 * 60,
  };
}

// Go's JSON encoder sorts map keys. Keep the signed request identical on both sides.
export function machineRequestHash(body: Record<string, unknown>): string {
  const fields: Record<string, string> = {};
  for (const key of ["audience", "public_key", "target", "user"]) {
    if (body[key] !== undefined) {
      if (typeof body[key] !== "string") throw new DeviceError("invalid_request", 400, `${key} must be a string`);
      fields[key] = body[key] as string;
    }
  }
  return createHash("sha256").update(JSON.stringify(fields)).digest("hex");
}

export function machineSshPrincipal(subject: string, target: string, user: string, apps: Record<string, unknown>): string {
  if (!/^[a-z0-9][a-z0-9.-]{0,252}$/.test(target) || !/^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$/.test(user)) {
    throw new DeviceError("invalid_request", 400, "invalid SSH target or user");
  }
  const grants = apps.ssh;
  if (!Array.isArray(grants) || !grants.some((g) => g?.target === target && g?.user === user)) {
    throw new DeviceError("access_denied", 403, "this machine has no grant for that SSH account");
  }
  return `${subject}@${target}/${user}`;
}
