// Local copy of the host-pattern matcher that better-auth uses internally
// (better-auth/dist/utils/wildcard.mjs). Vended here rather than imported
// because deep-importing from a dependency's compiled output couples us to
// its internal layout. The semantics are the canonical ones:
//
//   - `*` matches exactly one DNS label (no dots crossed).
//   - Patterns without `*` reduce to exact-string match.
//
// Examples:
//   matchWildcard("https://*.tank.dev.romaine.life",
//                 "https://tank-operator-slot-1.tank.dev.romaine.life")
//     → true
//   matchWildcard("https://*.tank.dev.romaine.life",
//                 "https://a.b.tank.dev.romaine.life")
//     → false  (* matches one label, not "a.b")
//   matchWildcard("https://tank.romaine.life", "https://tank.romaine.life")
//     → true   (no `*` → exact match)
export function matchWildcard(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp("^" + escaped.replace(/\*/g, "[^.]*") + "$");
  return regex.test(value);
}

/**
 * Wildcard format contract for entries that glimmung's reconciler is allowed
 * to install into the managed_origin store (and, by extension, into the
 * trustedOrigins / CORS allowlist):
 *
 *  - Must start with `https://` (no `http`, no other schemes).
 *  - Authority must contain exactly one `*` and it must be the leftmost
 *    DNS label as a whole (`*.example.com`, not `*foo.example.com` or
 *    `foo.*.example.com`).
 *  - No path, query, fragment, or port.
 *  - At least three labels (`*.example.com` minimum).
 *
 * This is strict on purpose. Glimmung derives the wildcard mechanically
 * from `native_standby_dns.record_base`; nothing legitimate needs more
 * flexibility. A laxer validator widens the attack surface that the
 * trustedOrigins / CORS allowlist guards.
 */
export function validateWildcard(wildcard: string): void {
  if (typeof wildcard !== "string") {
    throw new Error("wildcard must be a string");
  }
  if (!wildcard.startsWith("https://")) {
    throw new Error(`wildcard must start with https://: ${wildcard}`);
  }
  const authority = wildcard.slice("https://".length);
  if (authority.includes("/") || authority.includes("?") || authority.includes("#")) {
    throw new Error(`wildcard must not contain path/query/fragment: ${wildcard}`);
  }
  if (authority.includes(":")) {
    throw new Error(`wildcard must not contain a port: ${wildcard}`);
  }
  const stars = (authority.match(/\*/g) ?? []).length;
  if (stars !== 1) {
    throw new Error(`wildcard host must contain exactly one *: ${wildcard}`);
  }
  const labels = authority.split(".");
  if (labels[0] !== "*") {
    throw new Error(`wildcard's * must be the whole leftmost label: ${wildcard}`);
  }
  for (let i = 1; i < labels.length; i++) {
    if (labels[i].includes("*")) {
      throw new Error(`wildcard's * must be the leftmost label only: ${wildcard}`);
    }
    if (labels[i].length === 0) {
      throw new Error(`wildcard host must not contain empty labels: ${wildcard}`);
    }
  }
  if (labels.length < 3) {
    throw new Error(
      `wildcard host must have at least three labels (e.g. *.foo.bar): ${wildcard}`,
    );
  }
}
