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

const MSFT_LOGO = raw(`<svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>`);
const GOOGLE_LOGO = raw(`<svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.26c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/></svg>`);

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
          <button class="btn" type="submit">${MSFT_LOGO} Begin · Microsoft</button>
        </form>
        <form method="POST" action="/sign-in/google" style="display: inline">
          <button class="btn" type="submit">${GOOGLE_LOGO} Begin · Google</button>
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
      <span class="badge ${claims.role === "admin" ? "badge-admin" : ""}">${claims.role === "admin" ? "Blade Runner" : "Citizen"}</span>
    </div>

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
