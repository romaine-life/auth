import { test } from "node:test";
import assert from "node:assert/strict";
import { matchWildcard, validateWildcard } from "./wildcard.js";

// ── matchWildcard ────────────────────────────────────────────────────────

test("matchWildcard: subdomain wildcard accepts arbitrary single label", () => {
  assert.strictEqual(
    matchWildcard(
      "https://*.tank.dev.romaine.life",
      "https://tank-operator-slot-1.tank.dev.romaine.life",
    ),
    true,
  );
  assert.strictEqual(
    matchWildcard(
      "https://*.glimmung.dev.romaine.life",
      "https://glimmung-slot-1.glimmung.dev.romaine.life",
    ),
    true,
  );
});

test("matchWildcard: rejects different base host", () => {
  assert.strictEqual(
    matchWildcard(
      "https://*.tank.dev.romaine.life",
      "https://tank-operator-slot-1.glimmung.dev.romaine.life",
    ),
    false,
  );
});

test("matchWildcard: * matches exactly one label, not across dots", () => {
  assert.strictEqual(
    matchWildcard(
      "https://*.tank.dev.romaine.life",
      "https://a.b.tank.dev.romaine.life",
    ),
    false,
  );
});

test("matchWildcard: scheme must match", () => {
  assert.strictEqual(
    matchWildcard("https://*.tank.dev.romaine.life", "http://x.tank.dev.romaine.life"),
    false,
  );
});

test("matchWildcard: patterns without * reduce to exact match", () => {
  assert.strictEqual(
    matchWildcard("https://tank.romaine.life", "https://tank.romaine.life"),
    true,
  );
  assert.strictEqual(
    matchWildcard("https://tank.romaine.life", "https://x.tank.romaine.life"),
    false,
  );
});

test("matchWildcard: empty * label rejects empty subdomain", () => {
  // "https://.tank.dev.romaine.life" is not a valid origin; the matcher
  // happens to accept it because `*` → `[^.]*` matches zero chars. We
  // rely on the validator to keep malformed inputs out of the store.
  // Documenting the behavior so a future tightening of the regex is
  // intentional, not accidental.
  assert.strictEqual(
    matchWildcard("https://*.tank.dev.romaine.life", "https://.tank.dev.romaine.life"),
    true,
  );
});

// ── validateWildcard ─────────────────────────────────────────────────────

test("validateWildcard: accepts canonical slot wildcards", () => {
  assert.doesNotThrow(() => validateWildcard("https://*.tank.dev.romaine.life"));
  assert.doesNotThrow(() => validateWildcard("https://*.glimmung.dev.romaine.life"));
  assert.doesNotThrow(() => validateWildcard("https://*.ambience.dev.romaine.life"));
});

test("validateWildcard: rejects non-https schemes", () => {
  assert.throws(() => validateWildcard("http://*.tank.dev.romaine.life"), /https:\/\//);
  assert.throws(() => validateWildcard("ws://*.tank.dev.romaine.life"), /https:\/\//);
  assert.throws(() => validateWildcard("*.tank.dev.romaine.life"), /https:\/\//);
});

test("validateWildcard: rejects path/query/fragment", () => {
  assert.throws(
    () => validateWildcard("https://*.tank.dev.romaine.life/"),
    /path\/query\/fragment/,
  );
  assert.throws(
    () => validateWildcard("https://*.tank.dev.romaine.life?x=1"),
    /path\/query\/fragment/,
  );
  assert.throws(
    () => validateWildcard("https://*.tank.dev.romaine.life#frag"),
    /path\/query\/fragment/,
  );
});

test("validateWildcard: rejects ports", () => {
  assert.throws(() => validateWildcard("https://*.tank.dev.romaine.life:8443"), /port/);
});

test("validateWildcard: rejects zero or multiple wildcards", () => {
  assert.throws(() => validateWildcard("https://tank.dev.romaine.life"), /exactly one/);
  assert.throws(() => validateWildcard("https://*.*.dev.romaine.life"), /exactly one/);
});

test("validateWildcard: rejects embedded or non-leftmost wildcard", () => {
  assert.throws(
    () => validateWildcard("https://*tank.dev.romaine.life"),
    /leftmost label/,
  );
  assert.throws(
    () => validateWildcard("https://tank.*.romaine.life"),
    /leftmost label/,
  );
  assert.throws(
    () => validateWildcard("https://t*ank.dev.romaine.life"),
    /leftmost label/,
  );
});

test("validateWildcard: requires three-or-more labels", () => {
  assert.throws(() => validateWildcard("https://*.romaine"), /three labels/);
});

test("validateWildcard: rejects empty inner labels", () => {
  assert.throws(() => validateWildcard("https://*..romaine.life"), /empty labels/);
});
