import { test } from "node:test";
import assert from "node:assert/strict";
import { singleProviderSignInPath } from "./oidc-login-provider.js";

test("chess-tactics authorize bounce goes straight to Microsoft sign-in", () => {
  assert.equal(singleProviderSignInPath("chess-tactics"), "/sign-in/microsoft");
});

test("clients that support both providers keep the chooser", () => {
  assert.equal(singleProviderSignInPath("grafana"), null);
  assert.equal(singleProviderSignInPath("argocd"), null);
  assert.equal(singleProviderSignInPath("ambience"), null);
});

test("a plain landing-page visit (no client_id) keeps the chooser", () => {
  assert.equal(singleProviderSignInPath(undefined), null);
  assert.equal(singleProviderSignInPath(""), null);
});

test("inherited Object.prototype names never force a provider", () => {
  assert.equal(singleProviderSignInPath("toString"), null);
  assert.equal(singleProviderSignInPath("constructor"), null);
});
