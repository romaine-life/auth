#!/usr/bin/env node
// Migration guard: every auth.romaine.life JWT mint must go through
// `mintAuthJwt` in src/mint-jwt.ts. That helper is the single place
// that stamps the required-claim set asserted by the platform-wide
// verifier contract (REQUIRED_CLAIMS = ["exp", "iat", "iss", "role"]
// in nelsong6/romaine-auth-py and duplicated in
// nelsong6/mcp-github → auth_romaine.py).
//
// History: before this guard, two mint sites composed payloads
// independently. The admin bot-token site stamped iat explicitly;
// the service-exchange site relied on Better Auth's signJWT defaults,
// which don't set iat. The two paths drifted silently and every
// service token was rejected by mcp-github with `Token is missing the
// "iat" claim`. The shared mint helper is the deletion of the dual
// path; this script is the gate that prevents reintroducing it.
//
// Rule: `auth.api.signJWT` may appear ONLY in src/mint-jwt.ts. Any
// other occurrence under src/ — including in comments — is a CI fail.
// Reference the helper by name in markdown / README instead.

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = path.join(repoRoot, "src");
const SANCTIONED_FILE = path.join(srcRoot, "mint-jwt.ts");

// Match the call shape we are preventing. `auth.api.signJWT(` is the
// concrete Better Auth surface; matching the open-paren narrows out
// type references like `typeof auth.api.signJWT` and prose mentions
// like "Better Auth's signJWT" (the human description, no method
// access). Tightening the pattern keeps this guard from becoming a
// blanket ban on the phrase "signJWT" in comments.
const FORBIDDEN_PATTERN = /\bauth\.api\.signJWT\s*\(/g;

const failures = [];

async function walk(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full);
      continue;
    }
    if (!/\.(ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry.name)) continue;
    if (full === SANCTIONED_FILE) continue;
    const text = await fs.readFile(full, "utf8");
    for (const match of text.matchAll(FORBIDDEN_PATTERN)) {
      const { line, column } = lineAndColumn(text, match.index);
      const rel = path.relative(repoRoot, full);
      failures.push(`${rel}:${line}:${column} unsanctioned auth.api.signJWT call`);
    }
  }
}

await walk(srcRoot);

if (failures.length > 0) {
  console.error("Unsanctioned auth.api.signJWT call site(s) detected:");
  for (const failure of failures) console.error(`- ${failure}`);
  console.error("");
  console.error("All JWT mints must go through `mintAuthJwt` in src/mint-jwt.ts.");
  console.error("That helper owns the required-claim set asserted by every");
  console.error("auth.romaine.life consumer (exp, iat, iss, role, and for");
  console.error("role=service tokens, actor_email). Calling signJWT directly");
  console.error("re-opens the iat-drop drift this guard exists to prevent.");
  process.exit(1);
}

console.log("No unsanctioned auth.api.signJWT call sites in src/.");

function lineAndColumn(text, index) {
  const before = text.slice(0, index);
  const lines = before.split(/\r\n|\r|\n/);
  return {
    line: lines.length,
    column: lines[lines.length - 1].length + 1,
  };
}
