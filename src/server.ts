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

// Order + display-name mapping for the "Authorized Modules" grid on the
// dashboard. Mirrors the romaine.life app inventory; granted-state is
// derived per-user from the `apps` JSON blob (key presence == granted).
const APP_INVENTORY: Array<{ host: string; name: string; key: string }> = [
  { host: "homepage.romaine.life",   name: "homepage",    key: "homepage" },
  { host: "workout.romaine.life",    name: "kill-me",     key: "kill-me" },
  { host: "plants.romaine.life",     name: "plant-agent", key: "plant-agent" },
  { host: "invest.romaine.life",     name: "investing",   key: "investing" },
  { host: "house-hunt.romaine.life", name: "house-hunt",  key: "house-hunt" },
  { host: "diagrams.romaine.life",   name: "diagrams",    key: "diagrams" },
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

// ── Page chrome ────────────────────────────────────────────────────────────
// All views (landing, dashboard, admin) share a single SHELL: design tokens
// distilled from the Voight-Kampff handoff bundle (handoff README:
// "Tyrell · Authentication Division" — full VK theme, scanlines on, pyramid
// sigil prominent). Server-rendered HTML; small islands of JS for the
// real-time clock, rotating empathy prompts, off-world ticker, and the
// decoded/raw claims-tab toggle.

const STYLES = raw(`
:root {
  /* type */
  --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
  --font-primary: "Archivo", var(--font-sans);
  --font-mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "Consolas", "SF Mono", Menlo, monospace;

  /* radii / motion (from tank-operator tokens) */
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-pill: 9999px;
  --ease-out: cubic-bezier(0.22, 0.61, 0.36, 1);

  /* status (semantic) — pinned to VK warm palette */
  --status-online: #ffb073;
  --status-online-bg: rgba(255, 122, 58, 0.14);
  --status-pending: #b08858;
  --status-error: #ef6f6f;
  --status-error-bg: rgba(239, 111, 111, 0.12);
}

/* Voight-Kampff theme — orange CRT on inky brown. Single permanent theme;
   the prototype's tweaks-panel theme variants don't apply to production. */
body {
  /* accent + glow */
  --vk-accent: #ff7a3a;
  --vk-accent-soft: rgba(255, 122, 58, 0.16);
  --vk-iris-glow: 0 0 32px rgba(255, 107, 53, 0.35);
  --vk-grid: rgba(255, 122, 58, 0.04);

  /* warm-tinted grays — Tyrell room, after dark */
  --gray-950: #0c0907;
  --gray-900: #140e0a;
  --gray-850: #1c130d;
  --gray-800: #3a2614;
  --gray-700: #5a3a18;

  --bg-app: #0a0807;
  --bg-hover-soft: rgba(255, 255, 255, 0.04);

  --fg-primary: #ffffff;
  --fg-body: #e6cab0;
  --fg-secondary: #f4d8b8;
  --fg-muted: #b08858;
  --fg-faint: #8c5a26;

  --border-subtle: rgba(255, 122, 58, 0.12);
  --border-strong: rgba(255, 122, 58, 0.22);
}

* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  background: var(--bg-app);
  color: var(--fg-body);
  font-family: var(--font-sans);
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
  overflow-x: hidden;
}

/* faint dot-grid backdrop */
body::after {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image: radial-gradient(var(--vk-grid) 1px, transparent 1px);
  background-size: 24px 24px;
  mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
  -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
}

/* CRT scanlines */
body::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(
    to bottom,
    rgba(255, 122, 58, 0.04) 0px,
    rgba(255, 122, 58, 0.04) 1px,
    transparent 1px,
    transparent 3px
  );
  mix-blend-mode: screen;
}

button { cursor: pointer; font: inherit; background: transparent; color: inherit; border: none; padding: 0; outline: none; }
button:disabled { cursor: default; opacity: 0.55; }
a { color: var(--fg-secondary); text-decoration: none; }

/* ── Page shell ───────────────────────────────────────────────────── */
.stage {
  position: relative;
  z-index: 1;
  min-height: 100vh;
  display: grid;
  grid-template-rows: auto 1fr auto;
  padding: 28px clamp(20px, 5vw, 64px);
  max-width: 1080px;
  margin: 0 auto;
}

/* ── Top bar ─────────────────────────────────────────────────────── */
.topbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 24px; padding-bottom: 18px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand { display: flex; align-items: center; gap: 12px; font-family: var(--font-primary); }
.brand-mark {
  width: 32px; height: 32px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--vk-accent);
}
.brand-text { display: flex; flex-direction: column; gap: 2px; line-height: 1; }
.brand-text .lockup {
  font-size: 14px; font-weight: 500;
  letter-spacing: -0.005em; color: var(--fg-primary);
}
.brand-text .lockup .dim { color: var(--fg-faint); font-weight: 400; }
.brand-text .division {
  font-size: 10px; font-weight: 500;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--fg-faint);
}
.brand-text .lockup a { color: inherit; }
.topbar-meta {
  display: flex; align-items: center; gap: 16px;
  font-family: var(--font-mono); font-size: 11px;
  color: var(--fg-faint);
}
.topbar-meta .dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--status-online);
  box-shadow: 0 0 8px var(--status-online);
}
.topbar-meta .dot.is-pending { background: var(--status-pending); box-shadow: none; }
.topbar-meta .sep { color: var(--gray-800); }

/* ── Main column ─────────────────────────────────────────────────── */
.main {
  display: flex; align-items: flex-start; justify-content: center;
  padding: 24px 0; min-height: 0;
}
.main > * { margin-block: auto; width: 100%; }

/* ── Signed-out (landing) ────────────────────────────────────────── */
.vk-card {
  width: 100%; max-width: 520px;
  margin: 0 auto;
  display: flex; flex-direction: column; align-items: center;
  text-align: center; gap: 8px;
  animation: vk-fade-in 360ms var(--ease-out);
}
@keyframes vk-fade-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}
.vk-card .iris-wrap {
  position: relative;
  width: 168px; height: 168px;
  margin: 8px 0 18px;
  display: flex; align-items: center; justify-content: center;
  filter: drop-shadow(var(--vk-iris-glow));
}
.iris { color: var(--vk-accent); animation: iris-breathe 4.5s ease-in-out infinite; }
@keyframes iris-breathe {
  0%, 100% { opacity: 0.85; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.035); }
}
.vk-card h1 {
  font-family: var(--font-primary);
  font-size: 30px; font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--fg-primary);
  margin: 0;
}
.vk-card .subtitle {
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 0.25em;
  text-transform: uppercase; color: var(--fg-faint);
  margin: 4px 0 0;
}
.vk-card .lede {
  font-size: 14px; color: var(--fg-muted);
  max-width: 380px; margin: 16px auto 4px;
  line-height: 1.55; text-wrap: pretty;
}
.vk-card .lede code {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--fg-secondary);
  background: var(--gray-900);
  padding: 1px 5px; border-radius: var(--radius-sm);
}
.vk-card .epigraph {
  font-family: var(--font-mono);
  font-size: 12px; font-style: italic;
  color: var(--fg-faint);
  margin: 0 0 28px;
}

/* sign-in stack */
.signin-stack {
  display: flex; flex-direction: column; gap: 10px;
  width: 100%; max-width: 320px;
}
.signin-form { width: 100%; }
.signin-btn {
  display: flex; align-items: center; gap: 12px;
  width: 100%;
  height: 44px; padding: 0 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: var(--gray-900);
  color: var(--fg-primary);
  font-family: var(--font-primary);
  font-size: 14px; font-weight: 500;
  text-align: left;
  transition: background 120ms var(--ease-out), border-color 120ms var(--ease-out), transform 120ms var(--ease-out);
}
.signin-btn:hover { background: var(--gray-850); border-color: var(--gray-700); }
.signin-btn:active { transform: translateY(1px); }
.signin-btn .signin-label { flex: 1; }
.signin-btn .signin-meta {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.08em;
  color: var(--fg-faint); text-transform: uppercase;
}
.signin-btn .signin-logo { width: 20px; height: 20px; display: inline-flex; }

.vk-footnote {
  font-family: var(--font-mono);
  font-size: 11px; color: var(--fg-faint);
  margin: 24px 0 0; letter-spacing: 0.04em;
}
.vk-footnote code {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--fg-secondary);
  background: var(--gray-900);
  padding: 1px 5px; border-radius: var(--radius-sm);
}

/* ── Empathy prompt (signed-out) ─────────────────────────────────── */
.empathy-prompt {
  width: 100%; max-width: 460px;
  margin: 6px auto 26px;
  text-align: left;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-md);
  background: var(--gray-950);
  padding: 12px 14px 14px;
  position: relative;
}
.empathy-prompt::before {
  content: "";
  position: absolute; left: 0; top: 0; bottom: 0;
  width: 2px;
  background: var(--vk-accent); opacity: 0.4;
  border-radius: 1px;
}
.empathy-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.16em;
  text-transform: uppercase; color: var(--fg-faint);
  margin-bottom: 6px;
}
.empathy-num { color: var(--vk-accent); }
.empathy-body {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12.5px; line-height: 1.65;
  color: var(--fg-secondary);
  text-wrap: pretty;
  min-height: 4em;
  animation: empathy-fade 480ms var(--ease-out);
}
@keyframes empathy-fade {
  from { opacity: 0; transform: translateY(3px); }
  to { opacity: 1; transform: none; }
}

/* ── Signing-in overlay (cosmetic; appears on sign-in form submit) ── */
.vk-overlay {
  position: fixed; inset: 0; z-index: 60;
  background: rgba(10, 8, 7, 0.88);
  display: none;
  align-items: center; justify-content: center;
  flex-direction: column; gap: 18px;
  animation: vk-fade-in 220ms var(--ease-out);
  -webkit-backdrop-filter: blur(2px);
  backdrop-filter: blur(2px);
}
.vk-overlay.is-active { display: flex; }
.vk-overlay .iris-wrap { width: 168px; height: 168px; filter: drop-shadow(var(--vk-iris-glow)); }
.vk-overlay .iris { animation: iris-scan 1.8s linear infinite; }
@keyframes iris-scan {
  0%   { transform: rotate(0deg);   opacity: 1; }
  50%  { opacity: 0.7; }
  100% { transform: rotate(360deg); opacity: 1; }
}
.vk-overlay .overlay-title {
  font-family: var(--font-primary);
  font-size: 22px; font-weight: 600;
  color: var(--fg-primary);
  letter-spacing: -0.015em;
  margin: 0;
}
.vk-overlay .overlay-meta {
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 0.22em;
  text-transform: uppercase; color: var(--fg-faint);
}
.vk-overlay .term-log {
  font-family: var(--font-mono);
  font-size: 12px; color: var(--fg-muted);
  background: var(--gray-950);
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-md);
  padding: 12px 16px;
  width: min(420px, 90vw);
  text-align: left;
  white-space: pre-wrap;
}
.vk-overlay .term-log .ok { color: var(--status-online); }
.vk-overlay .term-log .info { color: var(--fg-body); }
.vk-overlay .term-log .dim { color: var(--fg-faint); }

/* ── Signed-in dashboard ─────────────────────────────────────────── */
.dash {
  width: 100%; max-width: 880px;
  margin: 0 auto;
  display: flex; flex-direction: column; gap: 20px;
  animation: vk-fade-in 360ms var(--ease-out);
}
.dash-head {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center; gap: 20px;
  padding: 18px 20px;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background:
    linear-gradient(180deg, rgba(255,255,255,0.018), rgba(255,255,255,0)),
    var(--gray-950);
}
.dash-head .iris-mini-wrap {
  width: 64px; height: 64px;
  display: flex; align-items: center; justify-content: center;
  filter: drop-shadow(var(--vk-iris-glow));
  color: var(--vk-accent);
}
.dash-head .head-text {
  display: flex; flex-direction: column; gap: 4px; min-width: 0;
}
.dash-head .head-name {
  font-family: var(--font-primary);
  font-size: 22px; font-weight: 600;
  letter-spacing: -0.015em;
  color: var(--fg-primary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dash-head .head-email {
  font-family: var(--font-mono);
  font-size: 12px; color: var(--fg-muted);
  word-break: break-all;
}
.dash-head .head-status {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.22em;
  text-transform: uppercase; color: var(--status-online);
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 2px;
}
.dash-head .head-status .blink-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--status-online);
  animation: blink 1.6s steps(2) infinite;
}
.dash-head .head-status.pending { color: var(--status-pending); }
.dash-head .head-status.pending .blink-dot { background: var(--status-pending); }
.dash-head .head-aside {
  display: flex; flex-direction: column; align-items: flex-end; gap: 8px;
}

/* NEXUS-7 designation row */
.head-designation {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--fg-faint);
  margin-top: 4px; flex-wrap: wrap;
}
.nexus-tag {
  padding: 1px 6px;
  border: 1px solid color-mix(in oklch, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
  letter-spacing: 0.16em;
}
.nexus-id { color: var(--fg-secondary); letter-spacing: 0.16em; }
.nexus-sep { color: var(--gray-800); }

/* role badge */
.role-badge {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 6px 10px;
  border-radius: var(--radius-pill);
  font-family: var(--font-primary);
  font-size: 11px; font-weight: 500;
  letter-spacing: 0.04em;
  border: 1px solid var(--gray-800);
  color: var(--fg-secondary);
  background: var(--gray-900);
  white-space: nowrap;
}
.role-badge.is-admin {
  color: var(--vk-accent);
  border-color: color-mix(in oklch, var(--vk-accent), transparent 70%);
  background: var(--vk-accent-soft);
  text-shadow: 0 0 8px color-mix(in oklch, var(--vk-accent), transparent 50%);
}
.role-badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

.end-btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: transparent;
  color: var(--fg-secondary);
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.04em;
  transition: background 120ms var(--ease-out), border-color 120ms var(--ease-out), color 120ms var(--ease-out);
}
.end-btn:hover {
  color: var(--status-error);
  border-color: color-mix(in oklch, var(--status-error), transparent 60%);
  background: var(--status-error-bg);
}
.end-btn.is-link { color: var(--vk-accent); }
.end-btn.is-link:hover {
  color: var(--vk-accent);
  border-color: color-mix(in oklch, var(--vk-accent), transparent 50%);
  background: var(--vk-accent-soft);
}

/* sections grid */
.dash-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.dash-grid > .col-span-2 { grid-column: span 2; }
@media (max-width: 720px) {
  .dash-grid { grid-template-columns: 1fr; }
  .dash-grid > .col-span-2 { grid-column: auto; }
  .dash-head {
    grid-template-columns: auto 1fr;
  }
  .dash-head .head-aside {
    grid-column: 1 / -1;
    flex-direction: row; align-items: center; justify-content: space-between;
  }
}

.section {
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background: var(--gray-950);
  overflow: hidden;
}
.section-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 14px 10px;
  gap: 12px;
  border-bottom: 1px solid var(--gray-800);
  background: rgba(255,255,255,0.012);
}
.section-head .title {
  display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap;
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--fg-secondary);
}
.section-head .title .sigil {
  font-family: var(--font-mono);
  color: var(--fg-faint); font-size: 11px;
  letter-spacing: 0.04em;
}
.section-head .title .hint {
  color: var(--fg-faint); text-transform: none;
  letter-spacing: 0; font-weight: 400;
  font-family: var(--font-mono); font-size: 11px;
  margin-left: 4px;
}
.section-head .count {
  font-family: var(--font-mono);
  font-size: 10px; color: var(--fg-faint);
}
.section-body { padding: 6px; }
.section-body .empty {
  padding: 18px 14px;
  font-family: var(--font-mono);
  font-size: 12px; font-style: italic;
  color: var(--fg-faint);
  text-align: center;
}

/* rows */
.row {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center; gap: 12px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  transition: background 120ms var(--ease-out);
}
.row:hover { background: var(--bg-hover-soft); }
.row .row-icon {
  width: 22px; height: 22px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--fg-secondary);
}
.row .row-main { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.row .row-primary {
  font-family: var(--font-primary);
  font-size: 13px; color: var(--fg-primary);
  font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .row-secondary {
  font-family: var(--font-mono);
  font-size: 11px; color: var(--fg-faint);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .pill {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  background: var(--gray-850);
  color: var(--fg-secondary);
  letter-spacing: 0.04em;
}
.row .pill.current {
  background: color-mix(in oklch, var(--status-online), transparent 80%);
  color: var(--status-online);
}

/* apps grid */
.apps {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 6px;
  padding: 8px;
}
.app-tile {
  display: flex; flex-direction: column; gap: 4px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-850);
  background: rgba(255,255,255,0.015);
  text-align: left;
  transition: background 120ms, border-color 120ms;
  color: inherit;
}
.app-tile:hover {
  background: var(--bg-hover-soft);
  border-color: var(--gray-800);
}
.app-tile.granted {
  border-color: color-mix(in oklch, var(--vk-accent), transparent 75%);
}
.app-tile.granted:hover {
  border-color: color-mix(in oklch, var(--vk-accent), transparent 55%);
}
.app-tile .app-name {
  font-family: var(--font-primary);
  font-size: 13px; color: var(--fg-primary);
  font-weight: 500;
}
.app-tile .app-host {
  font-family: var(--font-mono);
  font-size: 11px; color: var(--fg-muted);
}
.app-tile .app-host strong { color: var(--fg-primary); font-weight: 500; }
.app-tile .app-foot {
  display: flex; align-items: center; justify-content: space-between;
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--fg-faint);
  margin-top: 2px;
}
.app-tile.granted .app-foot .ok { color: var(--vk-accent); }

/* claims viewer */
.claims-wrap { padding: 8px; }
.claims {
  margin: 0;
  padding: 14px 16px;
  font-family: var(--font-mono);
  font-size: 12px; line-height: 1.65;
  color: var(--fg-body);
  background: #000;
  border-radius: var(--radius-md);
  overflow-x: auto;
  white-space: pre;
}
.claims .k { color: var(--vk-accent); }
.claims .s { color: var(--status-online); }
.claims .n { color: #c8b6f5; }
.claims .b { color: #e6b59a; }
.claims .p { color: var(--fg-faint); }
.claims-tabs { display: inline-flex; gap: 4px; align-items: center; }
.claims-tab,
.claims-copy {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  color: var(--fg-faint);
  transition: color 120ms, background 120ms;
}
.claims-tab.is-active { color: var(--fg-primary); background: var(--gray-850); }
.claims-tab:hover:not(.is-active),
.claims-copy:hover { color: var(--fg-primary); background: var(--gray-850); }
.claims-copy.is-copied { color: var(--status-online); }
.claims-pane[hidden] { display: none; }

/* admin form bits — reuse the dashboard chrome */
.admin-list { display: flex; flex-direction: column; gap: 12px; }
.admin-card {
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background: var(--gray-950);
  padding: 14px 16px;
}
.admin-card-head {
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 12px; margin-bottom: 10px;
  font-family: var(--font-mono);
  font-size: 12px; color: var(--fg-secondary);
}
.admin-card-head .when {
  font-size: 10px; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--fg-faint);
}
.admin-grid {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 8px 12px;
  align-items: center;
}
.admin-grid label {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--fg-faint);
}
.admin-grid input,
.admin-grid select,
.admin-grid textarea {
  background: #000;
  color: var(--fg-body);
  border: 1px solid var(--gray-800);
  padding: 6px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
  border-radius: var(--radius-sm);
  resize: vertical;
}
.admin-grid input:focus,
.admin-grid select:focus,
.admin-grid textarea:focus {
  outline: none; border-color: var(--vk-accent);
}
.admin-actions { display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
.admin-flash {
  border: 1px solid color-mix(in oklch, var(--vk-accent), transparent 60%);
  background: var(--vk-accent-soft);
  color: var(--vk-accent);
  padding: 10px 14px;
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: 12px; letter-spacing: 0.04em;
  margin-bottom: 14px;
}

/* generic action button used in admin / pending-state callout */
.btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: var(--gray-900);
  color: var(--fg-primary);
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.04em;
  transition: background 120ms, border-color 120ms;
}
.btn:hover { background: var(--gray-850); border-color: var(--gray-700); }

/* pending-review callout (when role=pending) */
.pending-callout {
  border: 1px solid color-mix(in oklch, var(--status-pending), transparent 50%);
  background: rgba(176, 136, 88, 0.08);
  color: var(--fg-muted);
  padding: 12px 14px;
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: 12px; line-height: 1.55;
}

/* ── Off-world ticker (footer) ───────────────────────────────────── */
.offworld-ticker {
  display: flex; align-items: center; gap: 12px;
  margin-top: 10px;
  padding: 6px 10px;
  border: 1px dashed var(--border-subtle);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 0.04em;
  color: var(--fg-muted);
  background: linear-gradient(90deg,
    color-mix(in oklch, var(--vk-accent), transparent 92%),
    transparent 60%);
  overflow: hidden;
}
.offworld-tag {
  flex-shrink: 0;
  font-size: 9px; font-weight: 600;
  letter-spacing: 0.22em; text-transform: uppercase;
  padding: 2px 6px;
  border: 1px solid color-mix(in oklch, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
}
.offworld-line {
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  animation: empathy-fade 480ms var(--ease-out);
}

/* ── Footer ──────────────────────────────────────────────────────── */
.footer {
  display: flex; flex-direction: column; gap: 0;
  padding-top: 14px;
  border-top: 1px solid var(--border-subtle);
  font-family: var(--font-mono);
  font-size: 11px; color: var(--fg-faint);
  letter-spacing: 0.04em;
}
.footer-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 18px; flex-wrap: wrap;
}
.footer .footer-links { display: inline-flex; gap: 14px; flex-wrap: wrap; }
.footer .footer-links a {
  color: var(--fg-faint);
  border-bottom: 1px dotted transparent;
  transition: color 120ms, border-color 120ms;
}
.footer .footer-links a:hover {
  color: var(--vk-accent);
  border-bottom-color: color-mix(in oklch, var(--vk-accent), transparent 60%);
}
.footer-sigil {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 0.3em;
}

/* ── Pyramid corner sigil ────────────────────────────────────────── */
.corner-mark {
  position: fixed; right: 18px; bottom: 16px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--fg-faint);
  letter-spacing: 0.2em; line-height: 1.15;
  text-align: right;
  pointer-events: none;
  z-index: 2; opacity: 0.55;
  white-space: pre;
}
.corner-mark .pyramid { color: var(--vk-accent); opacity: 0.7; }

@keyframes blink { 50% { opacity: 0; } }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 1ms !important;
    transition-duration: 1ms !important;
  }
}
`);

// ── SVG components (server-rendered, currentColor-strokeable) ──────────────

const IRIS_SVG = raw(`<svg class="iris" width="168" height="168" viewBox="0 0 168 168" fill="none" aria-hidden="true">
  <circle cx="84" cy="84" r="80" stroke="currentColor" stroke-width="0.7" opacity="0.25" />
  <circle cx="84" cy="84" r="66" stroke="currentColor" stroke-width="0.7" opacity="0.4" />
  <circle cx="84" cy="84" r="50" stroke="currentColor" stroke-width="1" />
  <circle cx="84" cy="84" r="36" stroke="currentColor" stroke-width="0.7" opacity="0.7" />
  <circle cx="84" cy="84" r="22" stroke="currentColor" stroke-width="0.5" opacity="0.85" />
  <circle cx="84" cy="84" r="9"  fill="currentColor" />
  ${(() => {
    // 24 iris filaments
    const lines: string[] = [];
    for (let i = 0; i < 24; i++) {
      const a = (i / 24) * Math.PI * 2;
      const x1 = (84 + Math.cos(a) * 22).toFixed(2);
      const y1 = (84 + Math.sin(a) * 22).toFixed(2);
      const x2 = (84 + Math.cos(a) * 36).toFixed(2);
      const y2 = (84 + Math.sin(a) * 36).toFixed(2);
      lines.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.55" />`);
    }
    return lines.join("");
  })()}
  <line x1="84" y1="2"   x2="84" y2="16"  stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="84" y1="152" x2="84" y2="166" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="2"   y1="84" x2="16"  y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="152" y1="84" x2="166" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  ${(() => {
    // tick marks at 60 positions, skipping every 5th
    const ticks: string[] = [];
    for (let i = 0; i < 60; i++) {
      if (i % 5 === 0) continue;
      const a = (i / 60) * Math.PI * 2;
      const r1 = 78, r2 = 80;
      const x1 = (84 + Math.cos(a) * r1).toFixed(2);
      const y1 = (84 + Math.sin(a) * r1).toFixed(2);
      const x2 = (84 + Math.cos(a) * r2).toFixed(2);
      const y2 = (84 + Math.sin(a) * r2).toFixed(2);
      ticks.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.3" />`);
    }
    return ticks.join("");
  })()}
</svg>`);

const IRIS_MINI_SVG = raw(`<svg width="56" height="56" viewBox="0 0 64 64" fill="none" aria-hidden="true">
  <circle cx="32" cy="32" r="28" stroke="currentColor" stroke-width="0.6" opacity="0.4" />
  <circle cx="32" cy="32" r="20" stroke="currentColor" stroke-width="0.8" />
  <circle cx="32" cy="32" r="12" stroke="currentColor" stroke-width="0.5" opacity="0.7" />
  <circle cx="32" cy="32" r="4"  fill="currentColor" />
  <line x1="32" y1="0"  x2="32" y2="6"  stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="32" y1="58" x2="32" y2="64" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="0"  y1="32" x2="6"  y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
  <line x1="58" y1="32" x2="64" y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5" />
</svg>`);

// Brand mark — small concentric rings + center pupil, currentColor.
const BRAND_MARK_SVG = raw(`<svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <circle cx="16" cy="16" r="14" stroke="currentColor" stroke-width="1" opacity="0.5" />
  <circle cx="16" cy="16" r="9"  stroke="currentColor" stroke-width="1" />
  <circle cx="16" cy="16" r="3"  fill="currentColor" />
</svg>`);

// Microsoft brand-compliant logo (four squares). Per Microsoft's
// identity-platform/howto-add-branding-in-apps spec.
const MICROSOFT_LOGO_SVG = raw(`<svg class="signin-logo" viewBox="0 0 21 21" aria-hidden="true">
  <rect x="1"  y="1"  width="9" height="9" fill="#F35325" />
  <rect x="11" y="1"  width="9" height="9" fill="#81BC06" />
  <rect x="1"  y="11" width="9" height="9" fill="#05A6F0" />
  <rect x="11" y="11" width="9" height="9" fill="#FFBA08" />
</svg>`);

const GOOGLE_LOGO_SVG = raw(`<svg class="signin-logo" viewBox="0 0 24 24" aria-hidden="true">
  <path fill="#EA4335" d="M12 10.2v3.9h5.5c-.24 1.5-1.7 4.3-5.5 4.3-3.3 0-6-2.7-6-6.1S8.7 6.2 12 6.2c1.9 0 3.1.8 3.9 1.5l2.6-2.5C16.9 3.7 14.6 2.7 12 2.7 6.9 2.7 2.8 6.8 2.8 12s4.1 9.3 9.2 9.3c5.3 0 8.8-3.7 8.8-9 0-.6-.1-1.1-.2-1.6H12z" />
  <path fill="#4285F4" d="M21 12.3c0-.6-.1-1.1-.2-1.6H12v3.9h5.5c-.2 1.3-1 2.4-2.1 3.1l3.3 2.5C20.8 18.7 21 15.7 21 12.3z" />
  <path fill="#FBBC05" d="M5.8 14.1c-.2-.6-.3-1.2-.3-1.9s.1-1.3.3-1.9L2.8 8.1A9.27 9.27 0 0 0 2.8 16l3-1.9z" />
</svg>`);

const CLOCK_ICON_SVG = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5" />
  <path d="M12 7v5l3 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
</svg>`);

const KEY_ICON_SVG = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="7" cy="12" r="3.5" stroke="currentColor" stroke-width="1.6" />
  <path d="M10.5 12h10M17.5 12v3M21 12v2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
</svg>`);

function providerGlyph(providerId: string) {
  if (providerId === "microsoft") return MICROSOFT_LOGO_SVG;
  if (providerId === "google") return GOOGLE_LOGO_SVG;
  return KEY_ICON_SVG;
}

const PYRAMID_CORNER = raw(`<div class="corner-mark" aria-hidden="true"><span class="pyramid">       ▲
      ▲ ▲
     ▲   ▲
    ▲  ◉  ▲
   ▲       ▲
  ▲▲▲▲▲▲▲▲▲</span>
TYRELL · NEXUS-7</div>`);

// ── Inline JS (clock, empathy cycler, ticker, claims tabs, sign-in overlay) ─

const INLINE_JS = raw(`
(function () {
  // Real-time UTC clock in the topbar.
  function formatNow() {
    var d = new Date();
    var z = function (n) { return String(n).padStart(2, "0"); };
    return z(d.getUTCHours()) + ":" + z(d.getUTCMinutes()) + ":" + z(d.getUTCSeconds()) + " UTC";
  }
  var clockEl = document.getElementById("vk-clock");
  if (clockEl) {
    clockEl.textContent = formatNow();
    setInterval(function () { clockEl.textContent = formatNow(); }, 1000);
  }

  // Empathy prompt cycler (signed-out only). Six prompts; same interrogative
  // rhythm as a VK question, written fresh — no movie dialogue.
  var EMPATHY_PROMPTS = [
    "You're walking through a corridor of mirrors. One reflection blinks before you do. You stop. Account for the time elapsed before you continue.",
    "A neighbour's terrier slips on the sidewalk. Its leg breaks audibly. The owner is three apartments away. Describe the next thirty seconds.",
    "Your grandmother sends a recording of her voice on your birthday. She has been dead nine years. You play it twice. Explain the second time.",
    "A child you don't recognise hands you a folded paper boat. You unfold it; the inside is blank. The child has gone. Describe your face in the next moment.",
    "An attendant at the duty-free counter asks if you have anything to declare. You are carrying only a paperback. You hesitate. Why.",
    "You wake at 4:11 a.m. to a perfect copy of your own handwriting on the wall above the bed. The handwriting is dry. Continue."
  ];
  var promptBody = document.getElementById("empathy-body");
  var promptNum = document.getElementById("empathy-num");
  if (promptBody && promptNum) {
    var pi = Math.floor(Math.random() * EMPATHY_PROMPTS.length);
    var paint = function () {
      promptBody.textContent = EMPATHY_PROMPTS[pi];
      var n = String(pi + 1).padStart(2, "0");
      var t = String(EMPATHY_PROMPTS.length).padStart(2, "0");
      promptNum.textContent = "Q · " + n + " / " + t;
      promptBody.style.animation = "none";
      void promptBody.offsetWidth;
      promptBody.style.animation = "";
    };
    paint();
    setInterval(function () {
      pi = (pi + 1) % EMPATHY_PROMPTS.length;
      paint();
    }, 9000);
  }

  // Off-world emigration ticker (footer). Cinematic atmosphere, derivative
  // copy — no movie dialogue.
  var OFFWORLD_PITCHES = [
    "off-world emigration · sectors 1138–2049 accepting applicants · embark Q3 2089",
    "a new sun. a new soil. carbon-stipend on signing · port terminal 14",
    "twin moons · pre-fab habitats · 8-year colonist warranty",
    "leave the dust behind. golden land. begin again — petition Tyrell relocation",
    "courier vessels weekly · standard manifest · no biometric exit fee",
    "sponsored: SHIMATA-DOMINGUEZ aerospace · clear-air corridors only"
  ];
  var tickerEl = document.getElementById("offworld-line");
  if (tickerEl) {
    var ti = 0;
    tickerEl.textContent = OFFWORLD_PITCHES[ti];
    setInterval(function () {
      ti = (ti + 1) % OFFWORLD_PITCHES.length;
      tickerEl.textContent = OFFWORLD_PITCHES[ti];
      tickerEl.style.animation = "none";
      void tickerEl.offsetWidth;
      tickerEl.style.animation = "";
    }, 6400);
  }

  // Subject Profile: decoded ↔ raw tab + copy-to-clipboard.
  var tabs = document.querySelectorAll(".claims-tab");
  var panes = document.querySelectorAll(".claims-pane");
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      var which = tab.getAttribute("data-pane");
      tabs.forEach(function (t) { t.classList.toggle("is-active", t === tab); });
      panes.forEach(function (p) { p.hidden = p.getAttribute("data-pane") !== which; });
    });
  });
  var copyBtn = document.getElementById("claims-copy");
  if (copyBtn) {
    copyBtn.addEventListener("click", function () {
      var src = document.getElementById("claims-source");
      if (!src) return;
      var text = src.textContent || "";
      try { navigator.clipboard && navigator.clipboard.writeText(text); } catch (_) {}
      copyBtn.classList.add("is-copied");
      copyBtn.textContent = "copied";
      setTimeout(function () {
        copyBtn.classList.remove("is-copied");
        copyBtn.textContent = "copy";
      }, 1400);
    });
  }

  // Sign-in cosmetic overlay. Intercept the form submit, show the iris-scan
  // overlay for a beat (so the user perceives the VK probe), then submit.
  // Degrades gracefully: with JS off the form posts directly.
  var overlay = document.getElementById("vk-overlay");
  var overlayLog = document.getElementById("vk-overlay-log");
  document.querySelectorAll(".signin-form").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!overlay) return;
      ev.preventDefault();
      var provider = form.getAttribute("data-provider") || "entra";
      var providerLabel = provider === "google" ? "Google OIDC" : "Microsoft Entra";
      var subtitleEl = document.getElementById("vk-overlay-subtitle");
      if (subtitleEl) subtitleEl.textContent = providerLabel;
      overlay.classList.add("is-active");
      var lines = [
        { d: 60,  t: "[001] resolving identity provider…",     c: "dim" },
        { d: 220, t: "[002] pkce challenge generated  (s256)", c: "info" },
        { d: 380, t: "[003] state cookie set  .romaine.life",  c: "info" },
        { d: 540, t: "[004] awaiting empathy response…",       c: "dim" },
        { d: 760, t: "[005] voight-kampff probe passed",       c: "ok" }
      ];
      if (overlayLog) overlayLog.innerHTML = "";
      lines.forEach(function (l) {
        setTimeout(function () {
          if (!overlayLog) return;
          var span = document.createElement("span");
          span.className = "line " + l.c;
          span.textContent = l.t + "\\n";
          overlayLog.appendChild(span);
        }, l.d);
      });
      setTimeout(function () { form.submit(); }, 1100);
    });
  });
})();
`);

// ── Pretty-printed JSON (server-side) for the Subject Profile decoded view ─
// Mirrors the design's PrettyClaims React component using Hono html spans.

type J = string | number | boolean | null | { [k: string]: J } | J[];

function prettyClaims(v: J, indent = 0): ReturnType<typeof html> {
  const pad = "  ".repeat(indent);
  if (v === null) return html`<span class="n">null</span>`;
  if (typeof v === "boolean") return html`<span class="b">${String(v)}</span>`;
  if (typeof v === "number") return html`<span class="n">${v}</span>`;
  if (typeof v === "string") return html`<span class="s">"${v}"</span>`;
  if (Array.isArray(v)) {
    if (v.length === 0) return html`[]`;
    return html`[
${v.map((x, i) => html`${pad}  ${prettyClaims(x, indent + 1)}${i < v.length - 1 ? "," : ""}
`)}${pad}]`;
  }
  const entries = Object.entries(v);
  if (entries.length === 0) return html`{}`;
  return html`{
${entries.map(([k, val], i) => html`${pad}  <span class="k">"${k}"</span><span class="p">:</span> ${prettyClaims(val, indent + 1)}${i < entries.length - 1 ? "," : ""}
`)}${pad}}`;
}

// ── Page chrome: TopBar + Footer ───────────────────────────────────────────

function renderTopBar(opts: { status?: "ok" | "pending"; signedIn?: boolean }) {
  const isPending = opts.status === "pending";
  return html`<div class="topbar">
    <div class="brand">
      <div class="brand-mark">${BRAND_MARK_SVG}</div>
      <div class="brand-text">
        <div class="lockup"><a href="/">voight-kampff</a> <span class="dim">/ auth.romaine.life</span></div>
        <div class="division">Tyrell · Authentication Division</div>
      </div>
    </div>
    <div class="topbar-meta">
      <span><span class="dot${isPending ? " is-pending" : ""}"></span> auth.romaine.life · ${isPending ? "pending" : "online"}</span>
      <span class="sep">·</span>
      <span>jwks rs256</span>
      <span class="sep">·</span>
      <span id="vk-clock">— UTC</span>
    </div>
  </div>`;
}

function renderFooter(opts: { signedIn?: boolean }) {
  return html`<div class="footer">
    <div class="footer-row">
      <div class="footer-links">
        <a href="/api/auth/jwks">/api/auth/jwks</a>
        <a href="/api/auth/get-session">/api/auth/get-session</a>
        ${opts.signedIn ? html`<a href="/api/auth/token">/api/auth/token</a>` : html``}
        <a href="https://github.com/nelsong6/auth">source</a>
      </div>
      <div class="footer-sigil">NEXUS-7</div>
    </div>
    <div class="offworld-ticker" aria-live="off">
      <span class="offworld-tag">OFF-WORLD</span>
      <span id="offworld-line" class="offworld-line">off-world emigration · sectors 1138–2049 accepting applicants · embark Q3 2089</span>
    </div>
  </div>`;
}

// Cosmetic sign-in overlay (hidden until JS shows it).
const SIGNIN_OVERLAY = html`<div id="vk-overlay" class="vk-overlay" role="status" aria-hidden="true">
  <div class="iris-wrap">${IRIS_SVG}</div>
  <p class="overlay-title">Calibrating…</p>
  <p class="overlay-meta" id="vk-overlay-subtitle">Microsoft Entra</p>
  <div class="term-log" id="vk-overlay-log"></div>
</div>`;

const SHELL = (title: string, body: ReturnType<typeof html>, opts: { status?: "ok" | "pending"; signedIn?: boolean } = {}) => html`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>${STYLES}</style>
  </head>
  <body>
    <div class="stage">
      ${renderTopBar({ status: opts.status, signedIn: opts.signedIn })}
      <div class="main">${body}</div>
      ${renderFooter({ signedIn: opts.signedIn })}
    </div>
    ${PYRAMID_CORNER}
    ${SIGNIN_OVERLAY}
    <script>${INLINE_JS}</script>
  </body>
</html>`;

// ── Routes ─────────────────────────────────────────────────────────────────

app.get("/", async (c) => {
  const result = await auth.api.getSession({ headers: c.req.raw.headers });

  // ── Anonymous landing ────────────────────────────────────────────────
  if (!result?.session) {
    return c.html(SHELL("Voight-Kampff — auth.romaine.life", html`
      <div class="vk-card">
        <div class="iris-wrap">${IRIS_SVG}</div>
        <h1>Voight-Kampff</h1>
        <p class="subtitle">Empathy Test · Subject Verification</p>
        <p class="lede">
          Examinee not identified. Authenticate to receive an RS256 token signed by this service; all <code>*.romaine.life</code> apps verify against this <code>jwks</code>.
        </p>
        <p class="epigraph">"more human than human" — Tyrell, 2019</p>

        <div class="empathy-prompt">
          <div class="empathy-head">
            <span id="empathy-num" class="empathy-num">Q · 01 / 06</span>
            <span class="empathy-meta">probe pre-roll · sample question</span>
          </div>
          <p id="empathy-body" class="empathy-body">You're walking through a corridor of mirrors. One reflection blinks before you do. You stop. Account for the time elapsed before you continue.</p>
        </div>

        <div class="signin-stack">
          <form method="POST" action="/sign-in/microsoft" class="signin-form" data-provider="microsoft">
            <button class="signin-btn" type="submit">
              ${MICROSOFT_LOGO_SVG}
              <span class="signin-label">Sign in with Microsoft</span>
              <span class="signin-meta">entra</span>
            </button>
          </form>
          <form method="POST" action="/sign-in/google" class="signin-form" data-provider="google">
            <button class="signin-btn" type="submit">
              ${GOOGLE_LOGO_SVG}
              <span class="signin-label">Sign in with Google</span>
              <span class="signin-meta">oidc</span>
            </button>
          </form>
        </div>

        <p class="vk-footnote">
          session scoped to <code>.romaine.life</code> · sso across every subdomain
        </p>
      </div>
    `));
  }

  // ── Authenticated dashboard ──────────────────────────────────────────
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
  const appsBlob = (() => {
    try { return JSON.parse((u as { apps?: string }).apps ?? "{}") as Record<string, unknown>; }
    catch { return {} as Record<string, unknown>; }
  })();
  const grantedKeys = new Set(Object.keys(appsBlob));

  const claims: Record<string, J> = {
    iss: "https://auth.romaine.life",
    sub: u.id,
    aud: "romaine.life",
    email: u.email,
    name: u.name,
    email_verified: u.emailVerified,
    role,
    apps: appsBlob as Record<string, J>,
  };
  const claimsJson = JSON.stringify(claims, null, 2);

  // Designation row — keep the prototype's NEXUS-7 framing but key off real
  // user data (incept date = createdAt month/year).
  const inc = u.createdAt
    ? `${String(u.createdAt.getUTCDate()).padStart(2, "0")}·${["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"][u.createdAt.getUTCMonth()]}·${u.createdAt.getUTCFullYear()}`
    : "—";
  const subjectShort = u.id.length > 12 ? `${u.id.slice(0, 6)}…${u.id.slice(-4)}` : u.id;

  const grantedCount = APP_INVENTORY.filter((a) => grantedKeys.has(a.key)).length;

  return c.html(SHELL(`${u.name} — Voight-Kampff`, html`
    <div class="dash">
      <div class="dash-head">
        <div class="iris-mini-wrap">${IRIS_MINI_SVG}</div>
        <div class="head-text">
          <div class="head-name">${u.name}</div>
          <div class="head-email">${u.email} · ${u.id}</div>
          <div class="head-designation">
            <span class="nexus-tag">NEXUS-7</span>
            <span class="nexus-id">EXP·${subjectShort.toUpperCase()}</span>
            <span class="nexus-sep">·</span>
            <span class="nexus-inc">inc. ${inc}</span>
          </div>
          <div class="head-status${role === "pending" ? " pending" : ""}">
            <span class="blink-dot"></span>
            ${role === "pending"
              ? "subject pending review · awaiting promotion"
              : "subject verified · empathy confirmed"}
          </div>
        </div>
        <div class="head-aside">
          <span class="role-badge${role === "admin" ? " is-admin" : ""}">
            <span class="dot"></span>
            ${role === "admin" ? "Blade Runner" : role === "user" ? "Citizen" : "Awaiting Review"}
          </span>
          <form method="POST" action="/sign-out" style="display: inline">
            <button class="end-btn" type="submit">End interview</button>
          </form>
        </div>
      </div>

      ${role === "pending" ? html`
        <div class="pending-callout">
          Authentication accepted, but the registry does not yet recognize you as a romaine.life subject.
          A blade runner must promote your status before downstream apps will admit you.
        </div>
      ` : html``}

      <div class="dash-grid">
        <!-- Provenance -->
        <div class="section">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span> Provenance</span>
            <span class="count">${accounts.length} linked</span>
          </div>
          <div class="section-body">
            ${accounts.length === 0
              ? html`<div class="empty">no linked accounts</div>`
              : accounts.map((a, i) => html`
                <div class="row">
                  <span class="row-icon">${providerGlyph(a.providerId)}</span>
                  <div class="row-main">
                    <div class="row-primary">${a.providerId}</div>
                    <div class="row-secondary">enrolled ${a.createdAt.toISOString().slice(0, 10)} · provider · ${a.providerId}</div>
                  </div>
                  <span class="row-meta">${i === 0
                    ? html`<span class="pill current">primary</span>`
                    : html`<span class="pill">linked</span>`}</span>
                </div>
              `)}
          </div>
        </div>

        <!-- Prior interrogations -->
        <div class="section">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span> Prior Interrogations</span>
            <span class="count">${sessions.length} active</span>
          </div>
          <div class="section-body">
            ${sessions.length === 0
              ? html`<div class="empty">no recent sessions</div>`
              : sessions.map((s) => {
                const when = s.createdAt.toISOString().replace("T", " ").slice(0, 16);
                const isCurrent = s.id === currentSessionId;
                return html`
                  <div class="row">
                    <span class="row-icon">${CLOCK_ICON_SVG}</span>
                    <div class="row-main">
                      <div class="row-primary">${when} UTC${isCurrent ? "  ·  this session" : ""}</div>
                      <div class="row-secondary">${s.userAgent ?? "—"} · ${s.ipAddress ?? "—"}</div>
                    </div>
                    ${isCurrent
                      ? html`<span class="pill current">current</span>`
                      : html`<span class="pill">linked</span>`}
                  </div>
                `;
              })}
          </div>
        </div>

        <!-- Authorized modules -->
        <div class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span> Authorized Modules</span>
            <span class="count">${grantedCount} of ${APP_INVENTORY.length} subdomains</span>
          </div>
          <div class="apps">
            ${APP_INVENTORY.map((a) => {
              const granted = grantedKeys.has(a.key);
              const prefs = appsBlob[a.key];
              const prefsCount = prefs && typeof prefs === "object" && !Array.isArray(prefs)
                ? Object.keys(prefs as Record<string, unknown>).length
                : 0;
              const subdomain = a.host.split(".")[0];
              const target = `https://${a.host}`;
              return html`
                <a class="app-tile${granted ? " granted" : ""}" href="${target}" target="_blank" rel="noreferrer noopener">
                  <span class="app-name">${a.name}</span>
                  <span class="app-host"><strong>${subdomain}</strong>.romaine.life</span>
                  <div class="app-foot">
                    <span class="${granted ? "ok" : ""}">${granted ? "● granted" : "○ no prefs"}</span>
                    <span>${prefsCount || "—"} prefs</span>
                  </div>
                </a>
              `;
            })}
          </div>
        </div>

        <!-- Subject profile (claims) -->
        <div class="section col-span-2">
          <div class="section-head">
            <span class="title">
              <span class="sigil">//</span> Subject Profile
              <span class="hint">token claims surfaced to romaine.life apps</span>
            </span>
            <span class="claims-tabs">
              <button type="button" class="claims-tab is-active" data-pane="decoded">decoded</button>
              <button type="button" class="claims-tab" data-pane="raw">raw</button>
              <button type="button" id="claims-copy" class="claims-copy">copy</button>
            </span>
          </div>
          <div class="claims-wrap">
            <pre id="claims-source" hidden>${claimsJson}</pre>
            <pre class="claims claims-pane" data-pane="decoded">${prettyClaims(claims as J)}</pre>
            <pre class="claims claims-pane" data-pane="raw" hidden>${claimsJson}</pre>
          </div>
        </div>
      </div>

      ${role === "admin" ? html`
        <div style="text-align: right;">
          <a class="btn" href="/admin">Tyrell Console →</a>
        </div>
      ` : html``}
    </div>
  `, { status: "ok", signedIn: true }));
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
    <div class="dash">
      <div class="dash-head" style="grid-template-columns: auto 1fr auto;">
        <div class="iris-mini-wrap">${IRIS_MINI_SVG}</div>
        <div class="head-text">
          <div class="head-name">Subject Registry</div>
          <div class="head-email">Tyrell · Operations Console</div>
          <div class="head-designation">
            <span class="nexus-tag">CONSOLE</span>
            <span class="nexus-id">AUTHENTICATE · CLASSIFY · RETIRE</span>
          </div>
        </div>
        <div class="head-aside">
          <a class="end-btn is-link" href="/">← Dashboard</a>
        </div>
      </div>

      ${flash ? html`<div class="admin-flash">${flash}</div>` : html``}

      <div class="section">
        <div class="section-head">
          <span class="title"><span class="sigil">//</span> Active Subjects</span>
          <span class="count">${users.length} on file</span>
        </div>
        <div class="section-body" style="padding: 12px;">
          ${users.length === 0
            ? html`<div class="empty">no subjects on file</div>`
            : html`<div class="admin-list">${users.map((u) => html`
              <form method="POST" action="/admin/users/${u.id}" class="admin-card">
                <div class="admin-card-head">
                  <span>${u.email}</span>
                  <span class="when">enrolled ${u.createdAt.toISOString().slice(0, 10)}</span>
                </div>
                <div class="admin-grid">
                  <label>Name</label>
                  <input name="name" value="${u.name}" />
                  <label>Role</label>
                  <select name="role">
                    <option value="user" ${u.role === "user" ? "selected" : ""}>citizen</option>
                    <option value="admin" ${u.role === "admin" ? "selected" : ""}>blade runner</option>
                  </select>
                  <label>Apps</label>
                  <textarea name="apps" rows="2">${u.apps}</textarea>
                </div>
                <div class="admin-actions">
                  <button class="btn" type="submit">Update</button>
                </div>
              </form>
            `)}</div>`}
        </div>
      </div>

      <div class="section">
        <div class="section-head">
          <span class="title"><span class="sigil">//</span> Enroll Subject</span>
          <span class="count">pre-create row</span>
        </div>
        <div class="section-body" style="padding: 12px;">
          <p style="color: var(--fg-faint); font-family: var(--font-mono); font-size: 11px; margin: 0 0 12px;">
            Pre-create a row before the subject completes their first sign-in. Better
            Auth's Microsoft flow will reconcile by email match when they arrive.
          </p>
          <form method="POST" action="/admin/users" class="admin-card">
            <div class="admin-grid">
              <label>Email</label>
              <input name="email" required placeholder="subject@example.com" />
              <label>Name</label>
              <input name="name" placeholder="Display name" />
              <label>Role</label>
              <select name="role">
                <option value="user">citizen</option>
                <option value="admin">blade runner</option>
              </select>
            </div>
            <div class="admin-actions">
              <button class="btn" type="submit">Enroll</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  `, { status: "ok", signedIn: true }));
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
