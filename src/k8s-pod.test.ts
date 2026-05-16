import { test } from "node:test";
import assert from "node:assert/strict";
import { extractLineage } from "./k8s-pod.js";

// extractLineage is the pure half of the k8s pod lookup — exercises the
// annotation contract without standing up an in-cluster API server. The
// HTTP-fetching half is covered end-to-end by tank-operator's integration
// path once Stage 4 lands (see nelsong6/tank-operator#486).

test("extractLineage: returns both annotations when present", () => {
  const result = extractLineage(
    {
      metadata: {
        annotations: {
          "tank-operator/owner-email": "user@example.com",
          "tank-operator/session-id": "session-abc",
        },
      },
    },
    "tank-operator-sessions",
    "claude-session-xyz",
  );
  assert.deepStrictEqual(result, {
    ownerEmail: "user@example.com",
    sessionId: "session-abc",
  });
});

test("extractLineage: trims whitespace inside annotation values", () => {
  const result = extractLineage(
    {
      metadata: {
        annotations: {
          "tank-operator/owner-email": "  user@example.com  ",
          "tank-operator/session-id": " session-abc ",
        },
      },
    },
    "ns",
    "pod",
  );
  assert.strictEqual(result.ownerEmail, "user@example.com");
  assert.strictEqual(result.sessionId, "session-abc");
});

test("extractLineage: throws when owner-email annotation is missing", () => {
  assert.throws(
    () =>
      extractLineage(
        { metadata: { annotations: { "tank-operator/session-id": "x" } } },
        "ns",
        "pod",
      ),
    /missing annotation tank-operator\/owner-email/,
  );
});

test("extractLineage: throws when session-id annotation is missing", () => {
  assert.throws(
    () =>
      extractLineage(
        { metadata: { annotations: { "tank-operator/owner-email": "u@x" } } },
        "ns",
        "pod",
      ),
    /missing annotation tank-operator\/session-id/,
  );
});

test("extractLineage: throws when annotations are absent entirely", () => {
  assert.throws(() => extractLineage({}, "ns", "pod"), /missing annotation/);
  assert.throws(() => extractLineage({ metadata: {} }, "ns", "pod"), /missing annotation/);
});

test("extractLineage: empty-string annotations are treated as missing (not vouched-for)", () => {
  assert.throws(
    () =>
      extractLineage(
        {
          metadata: {
            annotations: { "tank-operator/owner-email": "", "tank-operator/session-id": "x" },
          },
        },
        "ns",
        "pod",
      ),
    /missing annotation tank-operator\/owner-email/,
  );
});
