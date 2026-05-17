import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EntraExchangeError,
  extractExpClaim,
  pickEntraEmail,
} from "./entra-exchange-helpers.js";

// Pure helpers around the Entra-exchange path. The orchestrator and
// verifier are exercised by entra-auth.test.ts (JWKS fixture) and the
// downstream tank-operator integration suite.

test("pickEntraEmail: prefers email over preferred_username over upn", () => {
  assert.strictEqual(
    pickEntraEmail({ email: "a@x", preferred_username: "b@x", upn: "c@x" }),
    "a@x",
  );
  assert.strictEqual(
    pickEntraEmail({ preferred_username: "b@x", upn: "c@x" }),
    "b@x",
  );
  assert.strictEqual(pickEntraEmail({ upn: "c@x" }), "c@x");
});

test("pickEntraEmail: returns null when no candidate claim is present", () => {
  assert.strictEqual(pickEntraEmail({}), null);
  assert.strictEqual(pickEntraEmail({ sub: "x", oid: "y" }), null);
});

test("pickEntraEmail: returns null when candidate is empty or whitespace", () => {
  assert.strictEqual(pickEntraEmail({ email: "" }), null);
  assert.strictEqual(pickEntraEmail({ email: "   " }), null);
  // Falls through to the next candidate when the first is empty.
  assert.strictEqual(pickEntraEmail({ email: "", upn: "b@x" }), "b@x");
});

test("pickEntraEmail: trims whitespace around the resolved claim", () => {
  assert.strictEqual(pickEntraEmail({ email: "  a@x  " }), "a@x");
});

test("pickEntraEmail: ignores non-string candidate values (defense vs malformed tokens)", () => {
  assert.strictEqual(pickEntraEmail({ email: 42 as unknown as string }), null);
  assert.strictEqual(
    pickEntraEmail({ email: null as unknown as string, upn: "c@x" }),
    "c@x",
  );
});

test("extractExpClaim: decodes the exp claim from a well-formed JWT", () => {
  const payload = Buffer.from(JSON.stringify({ exp: 1234567890 })).toString(
    "base64url",
  );
  const jwt = `header.${payload}.signature`;
  assert.strictEqual(extractExpClaim(jwt), 1234567890);
});

test("extractExpClaim: throws on malformed JWT", () => {
  assert.throws(() => extractExpClaim("only.two"), /malformed JWT/);
  assert.throws(
    () => extractExpClaim("four.segments.is.too.many"),
    /malformed JWT/,
  );
});

test("extractExpClaim: throws when exp is missing or non-numeric", () => {
  const noExp = Buffer.from(JSON.stringify({ sub: "x" })).toString("base64url");
  assert.throws(
    () => extractExpClaim(`header.${noExp}.signature`),
    /missing numeric exp claim/,
  );
  const stringExp = Buffer.from(JSON.stringify({ exp: "soon" })).toString(
    "base64url",
  );
  assert.throws(
    () => extractExpClaim(`header.${stringExp}.signature`),
    /missing numeric exp claim/,
  );
});

test("EntraExchangeError: carries status + reason for the route handler to surface", () => {
  const err = new EntraExchangeError("nope", 403, "role_pending");
  assert.strictEqual(err.name, "EntraExchangeError");
  assert.strictEqual(err.status, 403);
  assert.strictEqual(err.reason, "role_pending");
  assert.strictEqual(err.message, "nope");
  assert.ok(err instanceof Error);
});
