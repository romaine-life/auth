import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

function source(path: string): string {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

test("auth does not own Tank break-glass approval routes", () => {
  const server = source("./server.ts");
  const metrics = source("./metrics.ts");

  for (const forbidden of [
    "/admin/git-break-glass/grants",
    "/admin/azure-break-glass/grants",
    "intent=git-break-glass",
    "intent=azure-break-glass",
    "tank_git_break_glass",
    "tank_azure_break_glass",
  ]) {
    assert.equal(server.includes(forbidden), false, `${forbidden} must stay out of auth`);
  }

  assert.equal(metrics.includes("auth_admin_git_break_glass_grants_total"), false);
  assert.equal(metrics.includes("auth_admin_azure_break_glass_grants_total"), false);
});
