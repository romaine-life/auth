import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAllowlist } from "./k8s-auth.js";

// Full JWT verification is exercised end-to-end by glimmung's integration
// path in nelsong6/glimmung#142 stage 2. Here we cover the pure parser
// that gates which (namespace, serviceAccount) pairs are accepted — that
// has been the bug vector for similar allowlists historically (whitespace,
// duplicates, missing separator).

test("parseAllowlist: trims whitespace around entries", () => {
  const result = parseAllowlist(" glimmung/glimmung ,  foo/bar ");
  assert.deepStrictEqual([...result].sort(), ["foo/bar", "glimmung/glimmung"]);
});

test("parseAllowlist: deduplicates identical entries", () => {
  const result = parseAllowlist("glimmung/glimmung,glimmung/glimmung");
  assert.deepStrictEqual([...result], ["glimmung/glimmung"]);
});

test("parseAllowlist: rejects entries without /", () => {
  const result = parseAllowlist("glimmung,foo/bar,nope");
  assert.deepStrictEqual([...result], ["foo/bar"]);
});

test("parseAllowlist: empty input → empty set", () => {
  assert.strictEqual(parseAllowlist("").size, 0);
  assert.strictEqual(parseAllowlist("   ").size, 0);
  assert.strictEqual(parseAllowlist(",,, ").size, 0);
});

test("parseAllowlist: preserves project-distinct same-name SAs", () => {
  const result = parseAllowlist("glimmung/glimmung,other/glimmung");
  assert.deepStrictEqual([...result].sort(), ["glimmung/glimmung", "other/glimmung"]);
});
