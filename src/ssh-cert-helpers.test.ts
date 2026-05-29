import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compilePrincipalPattern,
  validateSshCertRequest,
  SSH_CERT_MAX_KEY_ID_LENGTH,
  SSH_CERT_MAX_PRINCIPALS,
  type SshCertRequestProblem,
  type ValidatedSshCertRequest,
} from "./ssh-cert-helpers.js";
import {
  SSH_CERT_DEFAULT_TTL_SECONDS,
  SSH_CERT_MAX_TTL_SECONDS,
  SSH_CERT_MIN_TTL_SECONDS,
} from "./ssh-cert.js";

// validateSshCertRequest is the input gate the exchange orchestrator
// depends on for its 4xx surface — it runs BEFORE the SA-verify roundtrip
// and BEFORE the CA key touches anything. The (status, reason) pairs here
// are exactly what src/server.ts maps to JSON+HTTP, so drift on either
// side fails a test. The full verify→sign chain needs a live cluster OIDC
// issuer + the CA key and is exercised by the glimmung integration path
// and the crypto contract test in src/ssh-cert.test.ts.

const PATTERN = compilePrincipalPattern(undefined);
const VALID_PUBKEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc comment"; // shape only; not parsed here

function base(overrides: Record<string, unknown> = {}) {
  return {
    publicKey: VALID_PUBKEY,
    keyId: "glimmung-run:spirelens/7.1",
    principals: ["spirelens-agent"],
    principalPattern: PATTERN,
    ...overrides,
  };
}

function asProblem(
  v: SshCertRequestProblem | ValidatedSshCertRequest,
): SshCertRequestProblem {
  assert.ok("reason" in v && (v as SshCertRequestProblem).status === 400, "expected a problem");
  return v as SshCertRequestProblem;
}

function asValid(
  v: SshCertRequestProblem | ValidatedSshCertRequest,
): ValidatedSshCertRequest {
  assert.ok(!("status" in v), "expected a validated request");
  return v as ValidatedSshCertRequest;
}

test("happy path → validated request with defaults", () => {
  const v = asValid(validateSshCertRequest(base()));
  assert.deepStrictEqual(v.principals, ["spirelens-agent"]);
  assert.deepStrictEqual(v.extensions, ["permit-pty"]);
  assert.strictEqual(v.ttlSeconds, SSH_CERT_DEFAULT_TTL_SECONDS);
  assert.strictEqual(v.keyId, "glimmung-run:spirelens/7.1");
});

test("missing/empty public_key → denied_public_key", () => {
  for (const pk of ["", "   ", undefined, 42]) {
    const p = asProblem(validateSshCertRequest(base({ publicKey: pk })));
    assert.strictEqual(p.reason, "denied_public_key");
  }
});

test("missing/empty key_id → denied_key_id", () => {
  for (const k of ["", "   ", undefined, 7]) {
    const p = asProblem(validateSshCertRequest(base({ keyId: k })));
    assert.strictEqual(p.reason, "denied_key_id");
  }
});

test("over-long key_id → denied_key_id", () => {
  const p = asProblem(
    validateSshCertRequest(base({ keyId: "x".repeat(SSH_CERT_MAX_KEY_ID_LENGTH + 1) })),
  );
  assert.strictEqual(p.reason, "denied_key_id");
});

test("principals must be a non-empty array", () => {
  for (const principals of [[], undefined, "spirelens-agent", {}]) {
    const p = asProblem(validateSshCertRequest(base({ principals })));
    assert.strictEqual(p.reason, "denied_principal");
  }
});

test("principal not matching pattern → denied_principal (no root, no arbitrary login)", () => {
  for (const principal of ["root", "admin", "spirelens", "Spirelens-agent", "agent"]) {
    const p = asProblem(validateSshCertRequest(base({ principals: [principal] })));
    assert.strictEqual(p.reason, "denied_principal", `principal=${JSON.stringify(principal)}`);
  }
});

test("a principal that is valid only after trimming whitespace is accepted", () => {
  const v = asValid(validateSshCertRequest(base({ principals: ["  spirelens-agent  "] })));
  assert.deepStrictEqual(v.principals, ["spirelens-agent"]);
});

test("too many principals → denied_principal", () => {
  const many = Array.from({ length: SSH_CERT_MAX_PRINCIPALS + 1 }, (_, i) => `p${i}-agent`);
  const p = asProblem(validateSshCertRequest(base({ principals: many })));
  assert.strictEqual(p.reason, "denied_principal");
});

test("unknown extension → denied_extension (only permit-pty is allowed)", () => {
  for (const ext of ["permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"]) {
    const p = asProblem(validateSshCertRequest(base({ extensions: [ext] })));
    assert.strictEqual(p.reason, "denied_extension", `ext=${ext}`);
  }
});

test("explicit permit-pty extension is accepted", () => {
  const v = asValid(validateSshCertRequest(base({ extensions: ["permit-pty"] })));
  assert.deepStrictEqual(v.extensions, ["permit-pty"]);
});

test("non-array extensions → denied_extension", () => {
  const p = asProblem(validateSshCertRequest(base({ extensions: "permit-pty" })));
  assert.strictEqual(p.reason, "denied_extension");
});

test("ttl below min / above max / non-number → denied_ttl (rejected, never clamped)", () => {
  for (const ttl of [SSH_CERT_MIN_TTL_SECONDS - 1, SSH_CERT_MAX_TTL_SECONDS + 1, Number.NaN, "600"]) {
    const p = asProblem(validateSshCertRequest(base({ ttlSeconds: ttl })));
    assert.strictEqual(p.reason, "denied_ttl", `ttl=${ttl}`);
  }
});

test("ttl at the min and max boundaries is accepted", () => {
  for (const ttl of [SSH_CERT_MIN_TTL_SECONDS, SSH_CERT_MAX_TTL_SECONDS]) {
    const v = asValid(validateSshCertRequest(base({ ttlSeconds: ttl })));
    assert.strictEqual(v.ttlSeconds, ttl);
  }
});

test("compilePrincipalPattern falls back to the fail-closed default", () => {
  const re = compilePrincipalPattern("");
  assert.ok(re.test("spirelens-agent"));
  assert.ok(!re.test("root"));
});

test("compilePrincipalPattern honors a custom env pattern", () => {
  const re = compilePrincipalPattern("^svc-[a-z]+$");
  assert.ok(re.test("svc-build"));
  assert.ok(!re.test("spirelens-agent"));
});
