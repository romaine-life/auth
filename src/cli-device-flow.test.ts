import { test } from "node:test";
import assert from "node:assert/strict";
import {
  appendCallbackParams,
  hashSecret,
  normalizeUserCode,
  requireSelfIdentification,
  validateLoopbackRedirectUri,
  validatePkceInput,
  verifyPkceS256,
} from "./cli-device-flow.js";

test("normalizeUserCode: accepts pasted codes with spaces and hyphens", () => {
  assert.strictEqual(normalizeUserCode(" vk-ab12 cd34 "), "VKAB12CD34");
});

test("requireSelfIdentification: trims noisy input and requires a non-empty string", () => {
  assert.strictEqual(
    requireSelfIdentification("  Codex   in auth repo, asked by Nelson  "),
    "Codex in auth repo, asked by Nelson",
  );
  assert.throws(() => requireSelfIdentification(" "), /self_identification is required/);
  assert.throws(() => requireSelfIdentification(null), /self_identification is required/);
});

test("requireSelfIdentification: bounds stored display text", () => {
  assert.strictEqual(requireSelfIdentification("x".repeat(600)).length, 500);
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
