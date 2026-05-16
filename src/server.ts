import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { html, raw } from "hono/html";
import { logger } from "hono/logger";
import { eq, desc } from "drizzle-orm";
import { auth } from "./auth.js";
import { db } from "./db/client.js";
import { account, session, user } from "./db/schema.js";

const app = new Hono();
app.use("*", logger());

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
        --bg: #0f1419;
        --surface: #1a2028;
        --border: #2a3340;
        --text: #d7dbe0;
        --muted: #6b7280;
        --accent: #22d3ee;
        --danger: #f87171;
      }
      * { box-sizing: border-box; }
      body {
        font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
        background: var(--bg); color: var(--text);
        margin: 0; padding: 40px 20px; min-height: 100vh;
      }
      .container { max-width: 640px; margin: 0 auto; }
      h1 { font-size: 1.5rem; margin: 0 0 1rem; letter-spacing: 0.02em; }
      h2 { font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.08em;
           color: var(--muted); margin: 2rem 0 0.5rem; }
      p { line-height: 1.5; color: var(--text); }
      a { color: var(--accent); text-decoration: none; }
      a:hover { text-decoration: underline; }
      .card {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 6px; padding: 16px 20px; margin: 0.5rem 0;
      }
      .row { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
      .row .k { color: var(--muted); font-size: 0.85rem; }
      .row .v { font-size: 0.95rem; }
      .btn {
        display: inline-flex; align-items: center; gap: 10px;
        padding: 10px 18px; background: var(--surface); color: var(--text);
        border: 1px solid var(--border); border-radius: 4px; cursor: pointer;
        font-family: inherit; font-size: 0.95rem; text-decoration: none;
      }
      .btn:hover { border-color: var(--accent); }
      .btn-danger { color: var(--danger); border-color: var(--border); }
      .btn-danger:hover { border-color: var(--danger); }
      .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem; }
      .badge {
        display: inline-block; padding: 2px 8px; font-size: 0.75rem;
        border: 1px solid var(--border); border-radius: 3px; color: var(--muted);
      }
      .badge-admin { color: var(--accent); border-color: var(--accent); }
      pre.claims {
        background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
        padding: 12px; overflow-x: auto; font-size: 0.85rem; line-height: 1.5;
      }
      footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
               color: var(--muted); font-size: 0.8rem; }
    `)}</style>
  </head>
  <body><div class="container">${body}</div></body>
</html>`;

const MSFT_LOGO = raw(`<svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>`);
const GOOGLE_LOGO = raw(`<svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.26c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/></svg>`);

app.get("/", async (c) => {
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!result?.session) {
    return c.html(SHELL("Sign in — auth.romaine.life", html`
      <h1>auth.romaine.life</h1>
      <p>Identity for the romaine.life apps. Sign in to see what you're connected to.</p>
      <div class="actions">
        <form method="POST" action="/sign-in/microsoft" style="display: inline">
          <button class="btn" type="submit">${MSFT_LOGO} Sign in with Microsoft</button>
        </form>
        <form method="POST" action="/sign-in/google" style="display: inline">
          <button class="btn" type="submit">${GOOGLE_LOGO} Sign in with Google</button>
        </form>
      </div>
      <footer>
        <a href="/api/auth/jwks">JWKS</a> ·
        <a href="https://github.com/nelsong6/auth">source</a>
      </footer>
    `));
  }

  const u = result.user;
  const userId = u.id;

  // Linked providers + recent sessions, queried straight from the DB. Cheap
  // and avoids depending on Better Auth's evolving admin API surface.
  const accounts = await db.select().from(account).where(eq(account.userId, userId));
  const sessions = await db.select().from(session).where(eq(session.userId, userId)).orderBy(desc(session.createdAt)).limit(5);

  const claims = {
    sub: u.id,
    email: u.email,
    name: u.name,
    role: (u as { role?: string }).role ?? "user",
    apps: (() => { try { return JSON.parse((u as { apps?: string }).apps ?? "{}"); } catch { return {}; } })(),
  };

  return c.html(SHELL(`${u.name} — auth.romaine.life`, html`
    <h1>${u.name}</h1>
    <div class="row" style="margin-bottom: 1rem">
      <span>${u.email}</span>
      <span class="badge ${claims.role === "admin" ? "badge-admin" : ""}">${claims.role}</span>
    </div>

    <h2>Linked providers</h2>
    ${accounts.length === 0
      ? html`<div class="card"><span class="k">none</span></div>`
      : accounts.map((a) => html`
        <div class="card">
          <div class="row">
            <span class="v">${a.providerId}</span>
            <span class="k">linked ${a.createdAt.toISOString().slice(0, 10)}</span>
          </div>
        </div>
      `)}

    <h2>Recent sessions</h2>
    ${sessions.map((s) => html`
      <div class="card">
        <div class="row">
          <span class="v">${s.createdAt.toISOString().replace("T", " ").slice(0, 16)} UTC</span>
          <span class="k">${s.ipAddress ?? "no IP"}</span>
        </div>
        <div class="row" style="margin-top: 4px">
          <span class="k" style="font-size: 0.75rem; word-break: break-all">${s.userAgent ?? ""}</span>
        </div>
      </div>
    `)}

    <h2>JWT claims (what apps see)</h2>
    <pre class="claims">${JSON.stringify(claims, null, 2)}</pre>

    <div class="actions">
      <form method="POST" action="/sign-out" style="display: inline">
        <button class="btn btn-danger" type="submit">Sign out</button>
      </form>
    </div>

    <footer>
      <a href="/api/auth/token">my JWT</a> ·
      <a href="/api/auth/jwks">JWKS</a> ·
      <a href="https://github.com/nelsong6/auth">source</a>
    </footer>
  `));
});

// Trigger Better Auth's social sign-in server-side, then 302 the browser to
// the Microsoft/Google /authorize URL it returns. Keeps the user on this
// origin (no client JS needed to POST).
app.post("/sign-in/:provider{microsoft|google}", async (c) => {
  const provider = c.req.param("provider") as "microsoft" | "google";
  const result = await auth.api.signInSocial({
    body: { provider, callbackURL: "/" },
  });
  if (!result?.url) return c.text("sign-in failed", 500);
  return c.redirect(result.url);
});

app.post("/sign-out", async (c) => {
  await auth.api.signOut({ headers: c.req.raw.headers });
  return c.redirect("/", 302);
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`auth listening on :${info.port}`);
});
