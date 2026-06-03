#!/usr/bin/env node
// Migration guard for romaine-life/glimmung#142. Per-project slot wildcards
// (`https://*.{project}.dev.romaine.life`) live in the managed_origin
// table, populated by glimmung's reconciler. They MUST NOT be statically
// listed in auth source — that path is the deletion target this CI gate
// protects.
//
// Pattern flagged: any literal `https://*.<host>.dev.romaine.life` that
// appears in `src/auth.ts` or `src/server.ts`. Matches catch both
// `PROD_TRUSTED_ORIGINS` and `CROSS_APP_ORIGINS`.
//
// Comments in those files are scanned too — the pattern must not exist in
// source at all, including aspirational "we'll add this back" markers.
// Reference the issue in markdown / README instead.

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const scannedFiles = ["src/auth.ts", "src/server.ts"];

// Match `https://*.<anything>.dev.romaine.life`, optionally followed by a
// closing quote or path. The leading `https://` + `*.` is the load-bearing
// bit; what comes after the wildcard label is project-specific. We accept
// `https://` only (CORS allowlists wouldn't have other schemes).
const STATIC_SLOT_WILDCARD = /https:\/\/\*\.[a-z0-9-]+\.dev\.romaine\.life/g;

const failures = [];

for (const relPath of scannedFiles) {
  const filePath = path.join(repoRoot, relPath);
  let text;
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") continue;
    throw err;
  }
  for (const match of text.matchAll(STATIC_SLOT_WILDCARD)) {
    const { line, column } = lineAndColumn(text, match.index);
    failures.push(`${relPath}:${line}:${column} static slot wildcard: ${JSON.stringify(match[0])}`);
  }
}

if (failures.length > 0) {
  console.error("Static slot wildcard detected in auth source:");
  for (const failure of failures) console.error(`- ${failure}`);
  console.error("");
  console.error("Per-project slot wildcards live in the managed_origin table,");
  console.error("populated by glimmung's reconciler. See romaine-life/glimmung#142.");
  process.exit(1);
}

console.log("No static slot wildcards under .dev.romaine.life detected.");

function lineAndColumn(text, index) {
  const before = text.slice(0, index);
  const lines = before.split(/\r\n|\r|\n/);
  return {
    line: lines.length,
    column: lines[lines.length - 1].length + 1,
  };
}
