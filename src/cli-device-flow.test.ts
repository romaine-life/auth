import { test } from "node:test";
import assert from "node:assert/strict";
import {
  appendCallbackParams,
  decodeRequesterInfo,
  encodeRequesterInfo,
  hashSecret,
  normalizeUserCode,
  requireRequesterInfo,
  validateLoopbackRedirectUri,
  validatePkceInput,
  verifyPkceS256,
} from "./cli-device-flow.js";

test("normalizeUserCode: accepts pasted codes with spaces and hyphens", () => {
  assert.strictEqual(normalizeUserCode(" vk-ab12 cd34 "), "VKAB12CD34");
});

test("requireRequesterInfo: trims noisy input and requires all approval fields", () => {
  assert.deepStrictEqual(
    requireRequesterInfo({
      where_happening: "  Codex   in D:\\repos\\auth  ",
      intended_use: "  call   auth-protected romaine APIs  ",
      misc_identifier: "  anvil  ",
    }),
    {
      whereHappening: "Codex in D:\\repos\\auth",
      intendedUse: "call auth-protected romaine APIs",
      miscIdentifier: "anvil",
    },
  );
  assert.throws(() => requireRequesterInfo({}), /where_happening is required/);
  assert.throws(
    () => requireRequesterInfo({
      where_happening: "Codex",
      intended_use: "",
      misc_identifier: "anvil",
    }),
    /intended_use is required/,
  );
  assert.throws(
    () => requireRequesterInfo({
      where_happening: "Codex",
      intended_use: "API calls",
      misc_identifier: " ",
    }),
    /misc_identifier is required/,
  );
});

test("requireRequesterInfo: bounds stored display text", () => {
  const info = requireRequesterInfo({
    where_happening: "x".repeat(600),
    intended_use: "y".repeat(600),
    misc_identifier: "z".repeat(120),
  });
  assert.strictEqual(info.whereHappening.length, 500);
  assert.strictEqual(info.intendedUse.length, 500);
  assert.strictEqual(info.miscIdentifier.length, 80);
});

test("encodeRequesterInfo/decodeRequesterInfo: round trips structured display fields", () => {
  const info = {
    whereHappening: "Codex in D:\\repos\\auth",
    intendedUse: "call auth-protected romaine APIs",
    miscIdentifier: "anvil",
  };
  assert.deepStrictEqual(decodeRequesterInfo(encodeRequesterInfo(info)), info);
});

test("decodeRequesterInfo: preserves legacy plain self-identification strings", () => {
  assert.deepStrictEqual(decodeRequesterInfo("Codex legacy request"), {
    whereHappening: "Codex legacy request",
    intendedUse: "legacy request",
    miscIdentifier: "legacy",
  });
});

test("validateLoopbackRedirectUri: accepts localhost loopback callbacks", () => {
  assert.strictEqual(
    validateLoopbackRedirectUri("http://127.0.0.1:49152/callback"),
    "http://127.0.0.1:49152/callback",
  );
  assert.strictEqual(
    validateLoopbackRedirectUri("http://localhost:49152/callback"),
    "http://localhost:49152/callback",
  );
});

test("validateLoopbackRedirectUri: rejects non-loopback redirectors", () => {
  assert.throws(
    () => validateLoopbackRedirectUri("https://127.0.0.1:49152/callback"),
    /must use http/,
  );
  assert.throws(
    () => validateLoopbackRedirectUri("http://example.com:49152/callback"),
    /must target localhost/,
  );
  assert.throws(
    () => validateLoopbackRedirectUri("http://127.0.0.1/callback"),
    /explicit port/,
  );
});

test("validatePkceInput: requires S256 PKCE when redirect_uri is present", () => {
  assert.throws(
    () => validatePkceInput("http://127.0.0.1:49152/callback", null, null),
    /code_challenge is required/,
  );
  assert.throws(
    () => validatePkceInput(null, "not-long-enough", "S256"),
    /43-128/,
  );
  assert.throws(
    () => validatePkceInput(null, "a".repeat(43), "plain"),
    /only code_challenge_method=S256/,
  );
  assert.deepStrictEqual(
    validatePkceInput(null, "a".repeat(43), undefined),
    { codeChallenge: "a".repeat(43), codeChallengeMethod: "S256" },
  );
});

test("verifyPkceS256: validates the verifier against the challenge", () => {
  const verifier = "a".repeat(43);
  const challenge = hashSecret(verifier);
  assert.strictEqual(verifyPkceS256(verifier, challenge), true);
  assert.strictEqual(verifyPkceS256("b".repeat(43), challenge), false);
  assert.strictEqual(verifyPkceS256("short", challenge), false);
});

test("appendCallbackParams: preserves existing redirect query params", () => {
  assert.strictEqual(
    appendCallbackParams("http://127.0.0.1:49152/callback?x=1", "abc", "state-1"),
    "http://127.0.0.1:49152/callback?x=1&code=abc&state=state-1",
  );
});
