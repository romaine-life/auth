import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { eq, desc } from "drizzle-orm";
import { auth } from "./auth.js";
import { db } from "./db/client.js";
import { account, session, user } from "./db/schema.js";
import { renderLanding, renderDashboard, renderAdmin, shell } from "./render.js";

// Cross-origin fetches from .romaine.life apps that hit /api/auth/* to
// pick up a JWT (silent-exchange path) or check session need CORS
// response headers. Better Auth's `trustedOrigins` only governs CSRF
// and callbackURL validation — it does not set Access-Control-Allow-Origin.
// Hono's cors middleware fills that in, mirroring the same origin list.
const CROSS_APP_ORIGINS = [
  "https://homepage.romaine.life",
  "https://workout.romaine.life",
  "https://plants.romaine.life",
  "https://invest.romaine.life",
  "https://house-hunt.romaine.life",
  "https://diagrams.romaine.life",
  "https://tank.romaine.life",
  "http://localhost:5173",
  "http://localhost:5500",
];

const app = new Hono();
app.use("*", logger());

// Apply CORS only to the Better Auth surface — the dashboard at "/" is a
// same-origin HTML page and doesn't need ACA headers, and limiting scope
// keeps preflight cost off the unrelated routes.
app.use(
  "/api/auth/*",
  cors({
    origin: (origin) => (CROSS_APP_ORIGINS.includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type"],
    maxAge: 600,
  }),
);

app.get("/health", (c) => c.text("ok"));
app.get("/ready", (c) => c.text("ok"));

// Mount Better Auth at /api/auth/*. Handles sign-in flows, JWKS, sessions, etc.
app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

// ── Landing / dashboard ────────────────────────────────────────────────────
// Server-rendered HTML lives in src/render.ts so the design can be exercised
// (and snapshot-tested) without standing up Better Auth or the database. This
// file stays focused on routing, session resolution, and DB queries.

app.get("/", async (c) => {
  const result = await auth.api.getSession({ headers: c.req.raw.headers });

  if (!result?.session) {
    return c.html(shell("Voight-Kampff — auth.romaine.life", renderLanding()));
  }

  const u = result.user;
  const userId = u.id;
  const currentSessionId = result.session.id;

  const accounts = await db.select().from(account).where(eq(account.userId, userId));
  const sessions = await db
    .select()
    .from(session)
    .where(eq(session.userId, userId))
    .orderBy(desc(session.createdAt))
    .limit(8);

  const role = (u as { role?: string }).role ?? "user";
  const apps = (u as { apps?: string }).apps;

  return c.html(shell(`${u.name} — Voight-Kampff`, renderDashboard({
    user: {
      id: u.id,
      name: u.name,
      email: u.email,
      emailVerified: u.emailVerified,
      createdAt: u.createdAt ?? null,
      role,
      apps,
    },
    accounts: accounts.map((a) => ({
      id: a.id,
      providerId: a.providerId,
      createdAt: a.createdAt,
    })),
    sessions: sessions.map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      userAgent: s.userAgent,
      ipAddress: s.ipAddress,
    })),
    currentSessionId,
  }), { status: "ok", signedIn: true }));
});

// ── Admin console ──────────────────────────────────────────────────────────
// Single-page user manager — role + per-app `apps` JSON blob, plus name.
// Source of truth for the platform-wide admin list (formerly the
// `romaine-life-admin-emails` KV secret). Gated on role=admin claim.

async function requireAdmin(c: Context) {
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!result?.session) return { status: 302 as const, location: "/" };
  const role = (result.user as { role?: string }).role ?? "user";
  if (role !== "admin") return { status: 403 as const };
  return { ok: true as const, user: result.user };
}

app.get("/admin", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) {
    if (gate.status === 302) return c.redirect(gate.location);
    return c.text("forbidden", 403);
  }
  const users = await db.select().from(user).orderBy(desc(user.createdAt));
  const flash = c.req.query("ok");

  return c.html(shell("Tyrell Console — Subjects", renderAdmin({
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      role: u.role,
      apps: u.apps,
      createdAt: u.createdAt,
    })),
    flash,
  }), { status: "ok", signedIn: true }));
});

app.post("/admin/users", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  const form = await c.req.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const name = String(form.get("name") ?? "").trim() || email;
  const role = String(form.get("role") ?? "user");
  if (!email || !email.includes("@")) return c.text("invalid email", 400);
  if (role !== "admin" && role !== "user") return c.text("invalid role", 400);
  // Pre-create the row. Better Auth's Microsoft social provider matches on
  // email when the user signs in for the first time, so the row will gain
  // emailVerified=true + the Microsoft account link at that point.
  // crypto.randomUUID is fine for the user id; Better Auth itself uses
  // nanoid by default but accepts any unique string.
  const id = crypto.randomUUID();
  try {
    await db.insert(user).values({ id, email, name, role, emailVerified: false });
  } catch (err) {
    console.error("[admin/users] insert failed:", err);
    return c.text("insert failed (email likely already exists)", 400);
  }
  return c.redirect(`/admin?ok=enrolled+${encodeURIComponent(email)}`);
});

app.post("/admin/users/:id", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  const id = c.req.param("id");
  const form = await c.req.formData();
  const name = String(form.get("name") ?? "").trim();
  const role = String(form.get("role") ?? "user");
  const apps = String(form.get("apps") ?? "{}");
  if (!name) return c.text("name required", 400);
  if (role !== "admin" && role !== "user") return c.text("invalid role", 400);
  try {
    JSON.parse(apps);
  } catch {
    return c.text("apps must be valid JSON", 400);
  }
  await db.update(user)
    .set({ name, role, apps, updatedAt: new Date() })
    .where(eq(user.id, id));
  return c.redirect("/admin?ok=updated");
});

// ── Sign-in / sign-out ─────────────────────────────────────────────────────

// Better Auth's `asResponse: true` returns a full Response object including
// any Set-Cookie headers the call wants to set (e.g. the PKCE/state cookie
// for sign-in, the session-clear cookie for sign-out). We copy those across
// onto our own 302 so the browser has the cookies in hand before it follows
// the redirect. Without this, Microsoft's callback throws `state_mismatch`
// because the state cookie was never sent to the browser.
function copySetCookies(from: Response, to: Response): void {
  for (const cookie of from.headers.getSetCookie()) {
    to.headers.append("set-cookie", cookie);
  }
}

// Shared social-provider sign-in entrypoint. POST is the form-driven path
// from this service's own dashboard. GET with a `callbackURL` query param
// is the cross-app sign-in path: downstream apps (e.g. tank.romaine.life)
// link here with their post-sign-in URL and the user gets redirected back
// to the app after the IdP completes. Better Auth validates callbackURL
// against `trustedOrigins` in auth.ts — passing an unlisted origin throws.
async function socialSignInRedirect(c: Context, provider: "microsoft" | "google", callbackURL: string) {
  try {
    const authRes = await auth.api.signInSocial({
      body: { provider, callbackURL },
      headers: c.req.raw.headers,
      asResponse: true,
    });
    if (!authRes.ok) {
      console.error(`[sign-in:${provider}] better-auth returned`, authRes.status, await authRes.text());
      return c.text("sign-in failed", 500);
    }
    const data = await authRes.json() as { url?: string };
    if (!data.url) {
      console.error(`[sign-in:${provider}] better-auth response missing url`, data);
      return c.text("sign-in failed", 500);
    }
    const redirect = new Response(null, { status: 302, headers: { Location: data.url } });
    copySetCookies(authRes, redirect);
    return redirect;
  } catch (err) {
    console.error(`[sign-in:${provider}] threw:`, err);
    return c.text("sign-in failed", 500);
  }
}

app.post("/sign-in/microsoft", (c) => socialSignInRedirect(c, "microsoft", "/"));
app.get("/sign-in/microsoft", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return socialSignInRedirect(c, "microsoft", callbackURL);
});

app.post("/sign-in/google", (c) => socialSignInRedirect(c, "google", "/"));
app.get("/sign-in/google", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return socialSignInRedirect(c, "google", callbackURL);
});

app.post("/sign-out", async (c) => {
  try {
    const authRes = await auth.api.signOut({
      headers: c.req.raw.headers,
      asResponse: true,
    });
    const redirect = new Response(null, { status: 302, headers: { Location: "/" } });
    copySetCookies(authRes, redirect);
    return redirect;
  } catch (err) {
    console.error("[sign-out] threw:", err);
    return c.redirect("/");
  }
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`auth listening on :${info.port}`);
});
