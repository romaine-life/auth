import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_ROLES,
  MAX_TTL_SECONDS,
  REQUIRED_CLAIMS,
  TTL_SECONDS,
  assertBuilderClaimsPresent,
  buildAuthJwtPayload,
} from "./mint-jwt-helpers.js";

// These tests pin the JWT mint contract. They are the migration guard
// against the dual-issuer drift that caused mcp-github to reject every
// service token with `Token is missing the "iat" claim`: the old
// service-exchange path relied on Better Auth's signJWT defaults
// (which set iss/aud/exp but not iat); the bot-token path stamped iat
// explicitly. The contract test below pins the required-claim set
// asserted by every downstream verifier, so any future drift trips a
// red test before it ships.

const FIXED_NOW = 1_779_000_000;
const now = () => FIXED_NOW;

test("contract: builder stamps every claim required by downstream verifiers (except iss which signJWT owns)", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "u_abc",
      email: "u@example.com",
      name: "U",
      role: "user",
      apps: {},
    },
    now,
  );

  // REQUIRED_CLAIMS includes `iss` which Better Auth's signJWT fills
  // from baseURL — the builder doesn't own it, so we assert the rest
  // here and pin iss in the live signJWT-path test downstream.
  const builderOwned = REQUIRED_CLAIMS.filter((k) => k !== "iss");
  for (const claim of builderOwned) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(payload, claim),
      `payload missing required claim ${JSON.stringify(claim)}`,
    );
    const value = (payload as Record<string, unknown>)[claim];
    assert.ok(
      value !== undefined && value !== null && value !== "",
      `required claim ${JSON.stringify(claim)} was empty: ${JSON.stringify(value)}`,
    );
  }
});

test("iat is stamped to the injected clock — not left to signJWT defaults", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "u_1",
      email: "u@example.com",
      name: "U",
      role: "user",
      apps: {},
    },
    now,
  );
  assert.strictEqual(payload.iat, FIXED_NOW);
});

test("exp = iat + default TTL when no override given (service role -> 15min)", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "svc:tank:1",
      email: "pod-1@svc.romaine.life",
      name: "tank/pod-1",
      role: "service",
      apps: {},
      actorEmail: "nelson@romaine.life",
    },
    now,
  );
  assert.strictEqual(payload.iat, FIXED_NOW);
  assert.strictEqual(payload.exp, FIXED_NOW + TTL_SECONDS.service);
});

test("exp = iat + 24h when purpose=bot", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "u_admin",
      email: "admin@romaine.life",
      name: "Admin",
      role: "admin",
      apps: {},
      purpose: "bot",
    },
    now,
  );
  assert.strictEqual(payload.exp, FIXED_NOW + TTL_SECONDS.bot);
  assert.strictEqual(payload.purpose, "bot");
});

test("explicit ttlSeconds beats role/purpose default", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "u_1",
      email: "u@example.com",
      name: "U",
      role: "user",
      apps: {},
      ttlSeconds: 60,
    },
    now,
  );
  assert.strictEqual(payload.exp, FIXED_NOW + 60);
});

test("ttlSeconds > MAX_TTL_SECONDS throws — guards blast radius of a leaked token", () => {
  assert.throws(
    () =>
      buildAuthJwtPayload(
        {
          sub: "u_1",
          email: "u@example.com",
          name: "U",
          role: "user",
          apps: {},
          ttlSeconds: MAX_TTL_SECONDS + 1,
        },
        now,
      ),
    /exceeds MAX_TTL_SECONDS/,
  );
});

test("ttlSeconds must be a positive finite number", () => {
  for (const bad of [0, -1, NaN, Infinity]) {
    assert.throws(
      () =>
        buildAuthJwtPayload(
          {
            sub: "u_1",
            email: "u@example.com",
            name: "U",
            role: "user",
            apps: {},
            ttlSeconds: bad,
          },
          now,
        ),
      /ttlSeconds must be a positive number/,
    );
  }
});

test("role outside ALLOWED_ROLES is rejected (pending users can't be minted into a JWT)", () => {
  assert.throws(
    () =>
      buildAuthJwtPayload(
        {
          sub: "u_1",
          email: "u@example.com",
          name: "U",
          // @ts-expect-error - intentionally violating the type
          role: "pending",
          apps: {},
        },
        now,
      ),
    /role not in ALLOWED_ROLES/,
  );
});

test("role=service requires actorEmail — refuses to silently drop the actor binding", () => {
  assert.throws(
    () =>
      buildAuthJwtPayload(
        {
          sub: "svc:tank:1",
          email: "pod-1@svc.romaine.life",
          name: "tank/pod-1",
          role: "service",
          apps: {},
          // no actorEmail
        },
        now,
      ),
    /service tokens require a non-empty actorEmail/,
  );
  assert.throws(
    () =>
      buildAuthJwtPayload(
        {
          sub: "svc:tank:1",
          email: "pod-1@svc.romaine.life",
          name: "tank/pod-1",
          role: "service",
          apps: {},
          actorEmail: "   ",
        },
        now,
      ),
    /service tokens require a non-empty actorEmail/,
  );
});

test("non-service tokens must not carry actorEmail — surface for misuse", () => {
  assert.throws(
    () =>
      buildAuthJwtPayload(
        {
          sub: "u_1",
          email: "u@example.com",
          name: "U",
          role: "user",
          apps: {},
          actorEmail: "someone@example.com",
        },
        now,
      ),
    /non-service tokens must not carry actorEmail/,
  );
});

test("service token's actor_email lands on the payload (verifier reads this)", () => {
  const payload = buildAuthJwtPayload(
    {
      sub: "svc:tank:1",
      email: "pod-1@svc.romaine.life",
      name: "tank/pod-1",
      role: "service",
      apps: {},
      actorEmail: "nelson@romaine.life",
    },
    now,
  );
  assert.strictEqual(payload.actor_email, "nelson@romaine.life");
  assert.strictEqual(payload.role, "service");
});

test("assertBuilderClaimsPresent: trips on a hand-crafted payload that drops iat", () => {
  const payload = buildAuthJwtPayload(
    { sub: "u_1", email: "u@example.com", name: "U", role: "user", apps: {} },
    now,
  );
  // Simulate a future signing wrapper that strips iat — must not pass.
  const broken = { ...payload, iat: undefined } as unknown as Parameters<
    typeof assertBuilderClaimsPresent
  >[0];
  assert.throws(() => assertBuilderClaimsPresent(broken), /missing required claim "iat"/);
});

test("REQUIRED_CLAIMS and ALLOWED_ROLES are pinned by literal name list", () => {
  // Pin by literal — drift between this list and the downstream
  // verifier contract should be a code review event, not a silent
  // re-alignment. If you change either set, also update:
  //   - nelsong6/romaine-auth-py (require, ALLOWED_ROLES)
  //   - romaine-life/mcp-github → src/mcp_github/auth_romaine.py (require)
  assert.deepStrictEqual(REQUIRED_CLAIMS, ["exp", "iat", "iss", "role"]);
  assert.deepStrictEqual(ALLOWED_ROLES, ["admin", "user", "service"]);
});
