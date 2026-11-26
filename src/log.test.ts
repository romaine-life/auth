import { test } from "node:test";
import assert from "node:assert/strict";
import { Hono } from "hono";
import { parse, type Entry } from "@romaine-life/logline";
import { betterAuthLogger, errorText, log, outside, OUTSIDE_LIMIT, requestLog } from "./log.js";

// The lines auth writes to stdout while fn runs, each read back with logline's parse: a line
// that doesn't fit the standard fails the test.
async function captured(fn: () => unknown): Promise<Entry[]> {
  const lines: string[] = [];
  const write = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    lines.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  try {
    await fn();
  } finally {
    process.stdout.write = write;
  }
  return lines.join("").split("\n").filter(Boolean).map((line) => parse(line));
}

const fields = (entry: Entry) => Object.fromEntries(entry.fields);

test("log writes standard lines to stdout", async () => {
  const [entry] = await captured(() => log.warn("k8s exchange denied", { reason: "denied_token", status: 401, model: undefined, effort: null }));
  assert.equal(entry.level, "warn");
  assert.equal(entry.message, "k8s exchange denied");
  assert.deepEqual(fields(entry), { reason: "denied_token", status: "401" });
  assert.equal(entry.pid, process.pid);
});

test("outside masks credentials and caps the text", () => {
  assert.equal(outside("upstream said Authorization: Bearer abc.def.ghi"), "upstream said Authorization: Bearer ***");
  assert.equal(outside("/callback?code=xyz&state=abc"), "/callback?code=***&state=***");
  const long = outside("x".repeat(OUTSIDE_LIMIT * 2));
  assert.equal(long.length, OUTSIDE_LIMIT + 3);
});

test("errorText keeps the error's message and masks it", async () => {
  const text = errorText(new Error("token rejected: password=hunter2"));
  assert.match(text, /^Error: token rejected: password=\*\*\*/);
  assert.doesNotMatch(text, /hunter2/);
  const [entry] = await captured(() => log.error("startup failed", { error: text }));
  // A field keeps the stack's line breaks, escaped, so the line stays one line.
  assert.match(fields(entry).error, /^Error: token rejected: password=\*\*\*\n {4}at /);
});

test("requestLog writes one line per request, with no query", async () => {
  const app = new Hono();
  app.use("*", requestLog());
  app.get("/api/auth/callback/microsoft", (c) => c.text("ok"));
  app.get("/boom", () => {
    throw new Error("boom");
  });
  const entries = await captured(async () => {
    await app.request("/api/auth/callback/microsoft?code=secret-code&state=secret-state");
    await app.request("/boom");
  });
  assert.equal(entries.length, 2);
  const [ok, boom] = entries.map(fields);
  assert.equal(entries[0].level, "info");
  assert.equal(entries[0].message, "request");
  assert.equal(ok.method, "GET");
  assert.equal(ok.path, "/api/auth/callback/microsoft");
  assert.equal(ok.status, "200");
  assert.match(ok.ms, /^\d+$/);
  assert.equal(entries[1].level, "error");
  assert.equal(boom.status, "500");
  for (const entry of entries) assert.doesNotMatch(JSON.stringify(entry.fields), /secret/);
});

test("Better Auth's lines are standard lines, masked", async () => {
  const [entry] = await captured(() => betterAuthLogger.log("warn", "Please ensure '/.well-known/openid-configuration' exists.", { token: "abc" }));
  assert.equal(entry.level, "warn");
  assert.equal(entry.message, "better-auth");
  assert.equal(fields(entry).text, "Please ensure '/.well-known/openid-configuration' exists.");
  assert.equal(fields(entry).detail, '{"token":"***"}');
});
