import { test } from "node:test";
import assert from "node:assert/strict";
import { adminLoginRedirectPath } from "./admin-redirect.js";

test("adminLoginRedirectPath preserves the full admin URL as the sign-in callback", () => {
  const redirect = adminLoginRedirectPath(
    "https://auth.romaine.life/admin?ok=updated",
  );

  assert.equal(
    redirect,
    "/sign-in/microsoft?callbackURL=%2Fadmin%3Fok%3Dupdated",
  );
});

test("adminLoginRedirectPath does not leak the origin into the callback", () => {
  const redirect = adminLoginRedirectPath("https://auth.romaine.life/admin");
  assert.equal(redirect, "/sign-in/microsoft?callbackURL=%2Fadmin");
});
