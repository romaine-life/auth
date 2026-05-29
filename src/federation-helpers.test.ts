import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FEDERATION_DEFAULT_TTL_SECONDS,
  FEDERATION_MAX_TTL_SECONDS,
  audienceAllowed,
  federationSubject,
  matchAudiencePattern,
  parseAudienceAllowlist,
} from "./federation-helpers.js";

// These tests pin the pure-helper contract for the federation exchange.
// The end-to-end path (SA verify → audience gate → mint) is exercised
// in src/federation-exchange.test.ts.

test("parseAudienceAllowlist: trims, drops blanks, preserves order", () => {
  const result = parseAudienceAllowlist(
    " api.tailscale.com/*  ,, https://other.example.com , ",
  );
  assert.deepStrictEqual(result, [
    "api.tailscale.com/*",
    "https://other.example.com",
  ]);
});

test("parseAudienceAllowlist: empty input → empty list", () => {
  assert.deepStrictEqual(parseAudienceAllowlist(""), []);
  assert.deepStrictEqual(parseAudienceAllowlist("   "), []);
  assert.deepStrictEqual(parseAudienceAllowlist(",,, "), []);
});

test("matchAudiencePattern: literal patterns are exact-match", () => {
  assert.strictEqual(
    matchAudiencePattern("https://example.com", "https://example.com"),
    true,
  );
  assert.strictEqual(
    matchAudiencePattern("https://example.com", "https://example.com/"),
    false,
  );
  assert.strictEqual(matchAudiencePattern("a", "ab"), false);
});

test("matchAudiencePattern: trailing-* is a prefix match", () => {
  assert.strictEqual(
    matchAudiencePattern("api.tailscale.com/*", "api.tailscale.com/T6vFBk1dAa11CNTRL"),
    true,
  );
  assert.strictEqual(
    matchAudiencePattern("api.tailscale.com/*", "api.tailscale.com/"),
    true,
  );
  // Pattern's prefix is "api.tailscale.com/" — anything not starting
  // with that prefix is a non-match, including a string that omits
  // the slash boundary.
  assert.strictEqual(
    matchAudiencePattern("api.tailscale.com/*", "api.tailscale.com"),
    false,
  );
  assert.strictEqual(
    matchAudiencePattern("api.tailscale.com/*", "other.tailscale.com/foo"),
    false,
  );
});

test("matchAudiencePattern: multiple * is rejected (typo guard)", () => {
  // A multi-star pattern is almost always a misconfiguration; refuse
  // rather than guess regex-style intent. Same posture as the wildcard
  // matcher in src/wildcard.ts.
  assert.strictEqual(matchAudiencePattern("a*b*", "axby"), false);
  assert.strictEqual(matchAudiencePattern("*b*", "ab"), false);
});

test("matchAudiencePattern: middle-* is rejected (only trailing-* supported)", () => {
  assert.strictEqual(matchAudiencePattern("a*b", "axb"), false);
  assert.strictEqual(matchAudiencePattern("a*b", "ab"), false);
});

test("audienceAllowed: empty allowlist refuses everything (fail-closed)", () => {
  assert.strictEqual(audienceAllowed("anything", []), false);
  assert.strictEqual(audienceAllowed("api.tailscale.com/x", []), false);
});

test("audienceAllowed: empty audience is never allowed", () => {
  assert.strictEqual(audienceAllowed("", ["*"]), false);
});

test("audienceAllowed: matches any allowlist entry", () => {
  const list = ["literal", "api.tailscale.com/*", "https://other.example.com"];
  assert.strictEqual(audienceAllowed("literal", list), true);
  assert.strictEqual(audienceAllowed("api.tailscale.com/abc", list), true);
  assert.strictEqual(audienceAllowed("https://other.example.com", list), true);
  assert.strictEqual(audienceAllowed("nope", list), false);
});

test("federationSubject: deterministic k8s: prefix format", () => {
  assert.strictEqual(
    federationSubject("glimmung-runs", "glimmung-native-runner"),
    "k8s:glimmung-runs/glimmung-native-runner",
  );
});

test("federationSubject: trims whitespace", () => {
  assert.strictEqual(
    federationSubject(" ns ", " sa "),
    "k8s:ns/sa",
  );
});

test("federationSubject: refuses empty namespace or serviceAccount", () => {
  assert.throws(() => federationSubject("", "sa"), /namespace is empty/);
  assert.throws(() => federationSubject("ns", ""), /serviceAccount is empty/);
  assert.throws(() => federationSubject("   ", "sa"), /namespace is empty/);
});

test("TTL constants are sane: default <= max, both positive", () => {
  assert.ok(FEDERATION_DEFAULT_TTL_SECONDS > 0);
  assert.ok(FEDERATION_MAX_TTL_SECONDS >= FEDERATION_DEFAULT_TTL_SECONDS);
  // Pin the values so a future tweak surfaces in code review rather
  // than silently changing the external IdP trust window.
  assert.strictEqual(FEDERATION_DEFAULT_TTL_SECONDS, 5 * 60);
  assert.strictEqual(FEDERATION_MAX_TTL_SECONDS, 15 * 60);
});
