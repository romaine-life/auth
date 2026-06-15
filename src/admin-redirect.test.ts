import { test } from "node:test";
import assert from "node:assert/strict";
import { adminLoginRedirectPath } from "./admin-redirect.js";

test("adminLoginRedirectPath preserves the full admin approval URL as the sign-in callback", () => {
  const redirect = adminLoginRedirectPath(
    "https://auth.romaine.life/admin?intent=test-slot-model&session_id=76&model=claude-opus-4-8",
  );

  assert.equal(
    redirect,
    "/sign-in/microsoft?callbackURL=%2Fadmin%3Fintent%3Dtest-slot-model%26session_id%3D76%26model%3Dclaude-opus-4-8",
  );
});

test("adminLoginRedirectPath does not leak the origin into the callback", () => {
  const redirect = adminLoginRedirectPath("https://auth.romaine.life/admin");
  assert.equal(redirect, "/sign-in/microsoft?callbackURL=%2Fadmin");
});
