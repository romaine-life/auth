import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { html, raw } from "hono/html";
import { logger } from "hono/logger";
import { eq, desc } from "drizzle-orm";
import { auth } from "./auth.js";
import { db } from "./db/client.js";
import { account, session, user } from "./db/schema.js";

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
// Server-rendered HTML. Anonymous: welcome + sign-in buttons. Authenticated:
// user info, linked accounts, recent sessions. Lives here (not in a frontend)
// because the auth service's audience is anyone who needs to see/manage their
// own identity — pure content, no rich client state, SEO-irrelevant, and the
// session is already server-side.

const SHELL = (title: string, body: ReturnType<typeof html>) => html`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>${raw(`
      :root {
        --bg: #08070a;
        --surface: #14100c;
        --border: #3a2614;
        --text: #ff9d36;
        --dim: #8c5a26;
        --muted: #5a3a18;
        --accent: #ff6b35;
        --danger: #ff4d4d;
      }
      * { box-sizing: border-box; }
      html, body { margin: 0; padding: 0; }
      body {
        font-family: ui-monospace, "Berkeley Mono", "IBM Plex Mono", "SF Mono", Menlo, monospace;
        background: var(--bg); color: var(--text);
        padding: 40px 20px 80px; min-height: 100vh;
        font-size: 14px; line-height: 1.55;
      }
      /* CRT scanlines, very subtle */
      body::before {
        content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 1;
        background: repeating-linear-gradient(
          to bottom,
          rgba(255,157,54,0.02) 0px,
          rgba(255,157,54,0.02) 1px,
          transparent 1px,
          transparent 3px
        );
      }
      .container { position: relative; z-index: 2; max-width: 680px; margin: 0 auto; }
      .marquee {
        text-align: center; color: var(--dim); font-size: 11px;
        letter-spacing: 0.3em; margin-bottom: 24px;
      }
      .marquee .pyramid {
        display: block; color: var(--accent); white-space: pre;
        line-height: 1; margin-bottom: 12px; font-size: 10px;
      }
      .title {
        font-size: 28px; letter-spacing: 0.12em; text-transform: uppercase;
        text-align: center; margin: 8px 0 4px;
        text-shadow: 0 0 12px rgba(255,107,53,0.4);
      }
      .subtitle {
        text-align: center; color: var(--dim); font-size: 11px;
        letter-spacing: 0.25em; text-transform: uppercase; margin: 0 0 36px;
      }
      .iris {
        margin: 0 auto 32px; display: block; color: var(--accent);
        animation: iris-pulse 4s ease-in-out infinite;
      }
      @keyframes iris-pulse {
        0%, 100% { opacity: 0.85; transform: scale(1); }
        50%      { opacity: 1;    transform: scale(1.05); }
      }
      h2 {
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.18em;
        color: var(--dim); margin: 28px 0 8px;
        border-bottom: 1px dashed var(--muted); padding-bottom: 4px;
      }
      h2::before { content: "// "; color: var(--muted); }
      p { color: var(--text); }
      a { color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--muted); }
      a:hover { color: var(--text); border-bottom-color: var(--accent); }
      .card {
        background: var(--surface); border: 1px solid var(--border);
        padding: 12px 16px; margin: 6px 0;
      }
      .row { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
      .row .k { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; }
      .row .v { font-size: 13px; color: var(--text); }
      .btn {
        display: inline-flex; align-items: center; gap: 12px;
        padding: 12px 20px; background: transparent; color: var(--text);
        border: 1px solid var(--border); cursor: pointer;
        font-family: inherit; font-size: 13px; text-decoration: none;
        text-transform: uppercase; letter-spacing: 0.15em;
        transition: all 120ms ease;
      }
      .btn:hover { border-color: var(--accent); background: rgba(255,107,53,0.05);
                   box-shadow: 0 0 16px rgba(255,107,53,0.15); }
      .btn-danger { color: var(--danger); border-color: var(--muted); }
      .btn-danger:hover { border-color: var(--danger); background: rgba(255,77,77,0.05);
                          box-shadow: 0 0 16px rgba(255,77,77,0.15); }
      /* Microsoft brand-compliant "Sign in with Microsoft" button.
         Dark variant: #2F2F2F bg, #FFFFFF text, Segoe UI Regular 15px,
         41px tall, 21px logo with 12px padding. Per Microsoft's
         identity-platform/howto-add-branding-in-apps spec. */
      .btn-microsoft {
        display: inline-flex; align-items: center; gap: 12px;
        height: 41px; padding: 0 12px;
        background: #2F2F2F; color: #FFFFFF;
        border: 1px solid #8C8C8C;
        font-family: "Segoe UI", "Segoe UI Web (West European)",
                     -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
        font-size: 15px; font-weight: 400; letter-spacing: normal;
        text-transform: none; cursor: pointer;
      }
      .btn-microsoft:hover { background: #1f1f1f; box-shadow: 0 0 16px rgba(255,255,255,0.12); }
      .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 20px;
                 justify-content: center; }
      .badge {
        display: inline-block; padding: 2px 10px; font-size: 10px;
        border: 1px solid var(--border); color: var(--dim);
        text-transform: uppercase; letter-spacing: 0.18em;
      }
      .badge-admin { color: var(--accent); border-color: var(--accent);
                     text-shadow: 0 0 6px rgba(255,107,53,0.5); }
      pre.claims {
        background: #000; border: 1px solid var(--border);
        padding: 16px; overflow-x: auto; font-size: 12px; line-height: 1.6;
        color: var(--text); margin: 6px 0;
      }
      .examinee-line {
        display: flex; justify-content: space-between; align-items: center;
        margin: 24px 0; padding: 16px 20px;
        border: 1px solid var(--border); background: var(--surface);
      }
      .examinee-line .name { font-size: 18px; letter-spacing: 0.05em; }
      .examinee-line .email { color: var(--dim); font-size: 12px; }
      footer { margin-top: 48px; padding-top: 16px; border-top: 1px dashed var(--muted);
               color: var(--dim); font-size: 11px; letter-spacing: 0.1em;
               text-align: center; }
      footer a { color: var(--dim); border-bottom: none; }
      footer a:hover { color: var(--accent); }
      .blink { animation: blink 1.5s steps(2) infinite; }
      @keyframes blink { 50% { opacity: 0; } }
    `)}</style>
  </head>
  <body><div class="container">${body}</div></body>
</html>`;

const TYRELL_PYRAMID = raw(`<pre class="pyramid">       ▲
      ▲ ▲
     ▲   ▲
    ▲     ▲
   ▲       ▲
  ▲    ◉    ▲
 ▲           ▲
▲▲▲▲▲▲▲▲▲▲▲▲▲</pre>`);

const IRIS = raw(`<svg class="iris" width="80" height="80" viewBox="0 0 80 80" fill="none">
  <circle cx="40" cy="40" r="38" stroke="currentColor" stroke-width="0.7" opacity="0.4"/>
  <circle cx="40" cy="40" r="30" stroke="currentColor" stroke-width="1"/>
  <circle cx="40" cy="40" r="20" stroke="currentColor" stroke-width="0.7" opacity="0.6"/>
  <circle cx="40" cy="40" r="12" stroke="currentColor" stroke-width="0.5" opacity="0.7"/>
  <circle cx="40" cy="40" r="6" fill="currentColor"/>
  <line x1="40" y1="2" x2="40" y2="14" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="40" y1="66" x2="40" y2="78" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="2" y1="40" x2="14" y2="40" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="66" y1="40" x2="78" y2="40" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
</svg>`);

// Microsoft sign-in button per the official brand guidelines:
// https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-branding-in-apps
// 21x21 logo, four squares with the spec colors (#F35325 / #81BC06 / #05A6F0 / #FFBA08).
const MSFT_LOGO = raw(`<svg class="ms-logo" width="21" height="21" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#F35325"/><rect x="11" y="1" width="9" height="9" fill="#81BC06"/><rect x="1" y="11" width="9" height="9" fill="#05A6F0"/><rect x="11" y="11" width="9" height="9" fill="#FFBA08"/></svg>`);

app.get("/", async (c) => {
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!result?.session) {
    return c.html(SHELL("Voight-Kampff — auth.romaine.life", html`
      <div class="marquee">
        ${TYRELL_PYRAMID}
        TYRELL CORPORATION · AUTHENTICATION DIVISION
      </div>
      <h1 class="title">Voight-Kampff</h1>
      <p class="subtitle">Empathy Test · Subject Verification</p>
      ${IRIS}
      <p style="text-align: center; max-width: 460px; margin: 0 auto 8px;">
        Examinee not identified. The test begins on authentication.
      </p>
      <p style="text-align: center; color: var(--dim); font-size: 12px; max-width: 460px; margin: 0 auto;">
        "More human than human" is our motto.
      </p>
      <div class="actions">
        <form method="POST" action="/sign-in/microsoft" style="display: inline">
          <button class="btn-microsoft" type="submit">${MSFT_LOGO} Sign in with Microsoft</button>
        </form>
      </div>
      <footer>
        <a href="/api/auth/jwks">JWKS</a> ·
        <a href="https://github.com/nelsong6/auth">SOURCE</a> ·
        <span>NEXUS-7</span>
      </footer>
    `));
  }

  const u = result.user;
  const userId = u.id;

  const accounts = await db.select().from(account).where(eq(account.userId, userId));
  const sessions = await db.select().from(session).where(eq(session.userId, userId)).orderBy(desc(session.createdAt)).limit(5);

  const claims = {
    sub: u.id,
    email: u.email,
    name: u.name,
    role: (u as { role?: string }).role ?? "user",
    apps: (() => { try { return JSON.parse((u as { apps?: string }).apps ?? "{}"); } catch { return {}; } })(),
  };

  return c.html(SHELL(`${u.name} — Voight-Kampff`, html`
    <div class="marquee">
      ${TYRELL_PYRAMID}
      TYRELL CORPORATION · AUTHENTICATION DIVISION
    </div>
    <h1 class="title">Test Complete</h1>
    <p class="subtitle"><span class="blink">●</span>&nbsp;&nbsp;Subject Verified · Empathy Confirmed</p>

    <div class="examinee-line">
      <div>
        <div class="name">${u.name}</div>
        <div class="email">${u.email}</div>
      </div>
      <span class="badge ${claims.role === "admin" ? "badge-admin" : ""}">${claims.role === "admin" ? "Blade Runner" : claims.role === "user" ? "Citizen" : "Awaiting Review"}</span>
    </div>

    ${claims.role === "pending" ? html`
      <div class="card" style="border-color: var(--muted); margin-bottom: 16px;">
        <p style="margin: 0; color: var(--dim); font-size: 12px;">
          Authentication accepted, but the registry does not yet recognize you as a romaine.life subject.
          A blade runner must promote your status before downstream apps will admit you.
        </p>
      </div>
    ` : html``}

    <h2>Provenance</h2>
    ${accounts.length === 0
      ? html`<div class="card"><span class="k">no linked accounts</span></div>`
      : accounts.map((a) => html`
        <div class="card">
          <div class="row">
            <span class="v">${a.providerId}</span>
            <span class="k">enrolled ${a.createdAt.toISOString().slice(0, 10)}</span>
          </div>
        </div>
      `)}

    <h2>Prior Interrogations</h2>
    ${sessions.map((s) => html`
      <div class="card">
        <div class="row">
          <span class="v">${s.createdAt.toISOString().replace("T", " ").slice(0, 16)} UTC</span>
          <span class="k">${s.ipAddress ?? "—"}</span>
        </div>
        ${s.userAgent ? html`<div class="row" style="margin-top: 6px">
          <span class="k" style="font-size: 10px; word-break: break-all; letter-spacing: 0.05em">${s.userAgent}</span>
        </div>` : html``}
      </div>
    `)}

    <h2>Subject Profile</h2>
    <p style="color: var(--dim); font-size: 11px; margin: 0 0 8px;">
      Token claims surfaced to romaine.life apps:
    </p>
    <pre class="claims">${JSON.stringify(claims, null, 2)}</pre>

    <div class="actions">
      ${claims.role === "admin" ? html`
        <a class="btn" href="/admin">Tyrell Console</a>
      ` : html``}
      <form method="POST" action="/sign-out" style="display: inline">
        <button class="btn btn-danger" type="submit">End Interview</button>
      </form>
    </div>

    <footer>
      <a href="/api/auth/token">RAW TOKEN</a> ·
      <a href="/api/auth/jwks">JWKS</a> ·
      <a href="https://github.com/nelsong6/auth">SOURCE</a> ·
      <span>NEXUS-7</span>
    </footer>
  `));
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
  return c.html(SHELL("Tyrell Console — Subjects", html`
    <div class="marquee">
      ${TYRELL_PYRAMID}
      TYRELL CORPORATION · OPERATIONS CONSOLE
    </div>
    <h1 class="title">Subject Registry</h1>
    <p class="subtitle">Authenticate · Classify · Retire</p>

    ${flash ? html`<div class="card" style="border-color: var(--accent); margin-bottom: 16px;">
      <span class="v">${flash}</span>
    </div>` : html``}

    <h2>Active Subjects (${users.length})</h2>
    ${users.length === 0
      ? html`<div class="card"><span class="k">No subjects on file.</span></div>`
      : users.map((u) => html`
        <form method="POST" action="/admin/users/${u.id}" class="card" style="margin: 8px 0;">
          <div class="row" style="margin-bottom: 8px;">
            <span class="v" style="font-size: 14px;">${u.email}</span>
            <span class="k">${u.createdAt.toISOString().slice(0, 10)}</span>
          </div>
          <div style="display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; align-items: center;">
            <label class="k">Name</label>
            <input name="name" value="${u.name}" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 12px;" />
            <label class="k">Role</label>
            <select name="role" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 12px;">
              <option value="user" ${u.role === "user" ? "selected" : ""}>citizen</option>
              <option value="admin" ${u.role === "admin" ? "selected" : ""}>blade runner</option>
            </select>
            <label class="k">Apps</label>
            <textarea name="apps" rows="2" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 11px; resize: vertical;">${u.apps}</textarea>
          </div>
          <div class="actions" style="margin-top: 8px; justify-content: flex-start;">
            <button class="btn" type="submit">Update</button>
          </div>
        </form>
      `)}

    <h2>Enroll Subject</h2>
    <p style="color: var(--dim); font-size: 11px; margin: 0 0 8px;">
      Pre-create a row before the subject completes their first sign-in. Better
      Auth's Microsoft flow will reconcile by email match when they arrive.
    </p>
    <form method="POST" action="/admin/users" class="card">
      <div style="display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; align-items: center;">
        <label class="k">Email</label>
        <input name="email" required placeholder="subject@example.com" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 12px;" />
        <label class="k">Name</label>
        <input name="name" placeholder="Display name" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 12px;" />
        <label class="k">Role</label>
        <select name="role" style="background: #000; color: var(--text); border: 1px solid var(--border); padding: 6px 8px; font-family: inherit; font-size: 12px;">
          <option value="user">citizen</option>
          <option value="admin">blade runner</option>
        </select>
      </div>
      <div class="actions" style="margin-top: 12px; justify-content: flex-start;">
        <button class="btn" type="submit">Enroll</button>
      </div>
    </form>

    <div class="actions">
      <a class="btn" href="/">← Dashboard</a>
    </div>

    <footer>
      <span>BLADE RUNNER CONSOLE · NEXUS-7</span>
    </footer>
  `));
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

// Shared Microsoft sign-in entrypoint. POST is the form-driven path from
// this service's own dashboard. GET with a `callbackURL` query param is the
// cross-app sign-in path: downstream apps (e.g. tank.romaine.life) link
// here with their post-sign-in URL and the user gets redirected back to
// the app after Microsoft completes. Better Auth validates callbackURL
// against `trustedOrigins` in auth.ts — passing an unlisted origin throws.
async function microsoftSignInRedirect(c: Context, callbackURL: string) {
  try {
    const authRes = await auth.api.signInSocial({
      body: { provider: "microsoft", callbackURL },
      headers: c.req.raw.headers,
      asResponse: true,
    });
    if (!authRes.ok) {
      console.error("[sign-in] better-auth returned", authRes.status, await authRes.text());
      return c.text("sign-in failed", 500);
    }
    const data = await authRes.json() as { url?: string };
    if (!data.url) {
      console.error("[sign-in] better-auth response missing url", data);
      return c.text("sign-in failed", 500);
    }
    const redirect = new Response(null, { status: 302, headers: { Location: data.url } });
    copySetCookies(authRes, redirect);
    return redirect;
  } catch (err) {
    console.error("[sign-in] threw:", err);
    return c.text("sign-in failed", 500);
  }
}

app.post("/sign-in/microsoft", (c) => microsoftSignInRedirect(c, "/"));

app.get("/sign-in/microsoft", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return microsoftSignInRedirect(c, callbackURL);
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
