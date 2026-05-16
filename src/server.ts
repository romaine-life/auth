import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { html, raw } from "hono/html";
import { logger } from "hono/logger";
import { setCookie, deleteCookie, getCookie } from "hono/cookie";
import { eq, desc } from "drizzle-orm";
import { auth, resolveAllTrustedOrigins } from "./auth.js";
import { db } from "./db/client.js";
import { account, session, user } from "./db/schema.js";
import {
  deleteProjectOrigins,
  listManagedOrigins,
  listManagedOriginsByProject,
  replaceProjectOrigins,
} from "./managed_origins.js";
import { verifyK8sSAToken } from "./k8s_auth.js";
import { matchWildcard } from "./wildcard.js";

// Cross-origin fetches from .romaine.life apps that hit /api/auth/* to
// pick up a JWT (silent-exchange path) or check session need CORS
// response headers. Better Auth's `trustedOrigins` only governs CSRF
// and callbackURL validation — it does not set Access-Control-Allow-Origin.
// Hono's cors middleware fills that in, mirroring the trustedOrigins union
// (static prod peers + glimmung-managed slot wildcards). Pattern semantics:
// `*` matches one DNS label, no dots crossed. See src/wildcard.ts.
async function corsOriginMatcher(origin: string): Promise<string | null> {
  if (!origin) return null;
  for (const pattern of await resolveAllTrustedOrigins()) {
    if (matchWildcard(pattern, origin)) return origin;
  }
  return null;
}

const app = new Hono();
app.use("*", logger());

// Apply CORS only to the Better Auth surface — the dashboard at "/" is a
// same-origin HTML page and doesn't need ACA headers, and limiting scope
// keeps preflight cost off the unrelated routes.
app.use(
  "/api/auth/*",
  cors({
    origin: corsOriginMatcher,
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type"],
    maxAge: 600,
  }),
);

app.get("/health", (c) => c.text("ok"));
app.get("/ready", (c) => c.text("ok"));

// ── Admin: managed slot origins ────────────────────────────────────────────
// Glimmung's reconciler writes per-project slot wildcards here. The endpoint
// is intentionally NOT CORS-allowlisted — these are machine-to-machine calls
// from inside the cluster, never a browser caller. AuthN is the inbound
// caller's projected k8s SA token (RS256, signed by the AKS OIDC issuer),
// validated against the (namespace, serviceAccount) allowlist.
//
// See nelsong6/glimmung#142 for the cross-repo contract.
//
// In TEST_MODE we skip registration entirely — test slots have no DB and
// no inbound writers; a 404 is the correct surface there.
if (process.env.TEST_MODE !== "true") {
  app.use("/api/admin/origins/*", async (c, next) => {
    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      return c.json({ error: "missing bearer token" }, 401);
    }
    const token = header.slice("Bearer ".length).trim();
    try {
      // We don't currently surface the verified subject downstream — the
      // allowlist gate is the only authorization check today, and `glimmung`
      // is the only allowed caller. Persisting the subject on c.var would
      // require Hono Variables typing; skip until we have a real second
      // caller.
      await verifyK8sSAToken(token);
    } catch (e) {
      return c.json({ error: `unauthorized: ${(e as Error).message}` }, 401);
    }
    await next();
  });

  app.get("/api/admin/origins", async (c) => {
    const rows = await listManagedOrigins();
    return c.json({ origins: rows });
  });

  app.get("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    const wildcards = await listManagedOriginsByProject(project);
    return c.json({ project, wildcards });
  });

  app.put("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    let body: { wildcards?: unknown };
    try {
      body = (await c.req.json()) as { wildcards?: unknown };
    } catch {
      return c.json({ error: "invalid JSON body" }, 400);
    }
    if (
      !Array.isArray(body.wildcards) ||
      !body.wildcards.every((w) => typeof w === "string")
    ) {
      return c.json({ error: "body.wildcards must be a string array" }, 400);
    }
    try {
      await replaceProjectOrigins(project, body.wildcards as string[]);
    } catch (e) {
      return c.json({ error: (e as Error).message }, 422);
    }
    return c.json({
      project,
      wildcards: await listManagedOriginsByProject(project),
    });
  });

  app.delete("/api/admin/origins/:project", async (c) => {
    const project = c.req.param("project");
    await deleteProjectOrigins(project);
    return c.json({ project, wildcards: [] });
  });
}

// TEST_MODE flips every handler into fixture-data mode. Used by helm-issue
// per-slot deployments at *.auth.dev.romaine.life so operators can cruise
// the UI without standing up a dev DB or dev OAuth backend. The auth and
// db modules still init (with placeholder env), but their methods are
// never reached in test mode.
const TEST_MODE = process.env.TEST_MODE === "true";
const TEST_COOKIE = "auth-test-signed-in";
const TEST_COOKIE_DOMAIN = process.env.COOKIE_DOMAIN ?? undefined;

function setTestCookie(c: Context) {
  setCookie(c, TEST_COOKIE, "1", {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    maxAge: 86400,
    domain: TEST_COOKIE_DOMAIN,
  });
}
function clearTestCookie(c: Context) {
  deleteCookie(c, TEST_COOKIE, { path: "/", domain: TEST_COOKIE_DOMAIN });
}
function isTestSignedIn(c: Context): boolean {
  return getCookie(c, TEST_COOKIE) === "1";
}

if (TEST_MODE) {
  // Mock JWKS so the topbar JS that fetches `/api/auth/jwks` sees a kid and
  // renders it. Real Better Auth never gets invoked.
  app.get("/api/auth/jwks", (c) =>
    c.json({
      keys: [
        {
          kty: "RSA",
          use: "sig",
          alg: "RS256",
          kid: "test1234",
          n: "test-mode-public-key-modulus-placeholder",
          e: "AQAB",
        },
      ],
    }),
  );
} else {
  // Mount Better Auth at /api/auth/*. Handles sign-in flows, JWKS, sessions, etc.
  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));
}

// ── Landing / dashboard ────────────────────────────────────────────────────
// Server-rendered HTML. Anonymous: welcome + sign-in buttons. Authenticated:
// user info, linked accounts, recent sessions, granted apps, raw claims.
// Visual treatment: Voight-Kampff (Blade Runner / PKD) — amber CRT on inky
// brown, iris animation, off-world emigration ticker, pyramid corner mark.
// Design handoff from claude.ai/design lives in design-fetch/.

const BUILD = (process.env.GIT_SHA ?? "dev").slice(0, 7);

// Generate the iris SVG once at module load. Procedural geometry — 24
// filaments + 60 minor ticks (skipping every 5th) — same shape the design's
// React component renders, but rendered server-side as static markup.
function buildIris(): string {
  const filaments: string[] = [];
  for (let i = 0; i < 24; i++) {
    const a = (i / 24) * Math.PI * 2;
    const x1 = (84 + Math.cos(a) * 22).toFixed(2);
    const y1 = (84 + Math.sin(a) * 22).toFixed(2);
    const x2 = (84 + Math.cos(a) * 36).toFixed(2);
    const y2 = (84 + Math.sin(a) * 36).toFixed(2);
    filaments.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.55"/>`);
  }
  const ticks: string[] = [];
  for (let i = 0; i < 60; i++) {
    if (i % 5 === 0) continue;
    const a = (i / 60) * Math.PI * 2;
    const r1 = 78, r2 = 80;
    const x1 = (84 + Math.cos(a) * r1).toFixed(2);
    const y1 = (84 + Math.sin(a) * r1).toFixed(2);
    const x2 = (84 + Math.cos(a) * r2).toFixed(2);
    const y2 = (84 + Math.sin(a) * r2).toFixed(2);
    ticks.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="currentColor" stroke-width="0.5" opacity="0.3"/>`);
  }
  return `<svg class="iris" width="168" height="168" viewBox="0 0 168 168" fill="none" aria-hidden="true">
    <circle cx="84" cy="84" r="80" stroke="currentColor" stroke-width="0.7" opacity="0.25"/>
    <circle cx="84" cy="84" r="66" stroke="currentColor" stroke-width="0.7" opacity="0.4"/>
    <circle cx="84" cy="84" r="50" stroke="currentColor" stroke-width="1"/>
    <circle cx="84" cy="84" r="36" stroke="currentColor" stroke-width="0.7" opacity="0.7"/>
    <circle cx="84" cy="84" r="22" stroke="currentColor" stroke-width="0.5" opacity="0.85"/>
    <circle cx="84" cy="84" r="9" fill="currentColor"/>
    ${filaments.join("")}
    <line x1="84" y1="2" x2="84" y2="16" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="84" y1="152" x2="84" y2="166" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="2" y1="84" x2="16" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    <line x1="152" y1="84" x2="166" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
    ${ticks.join("")}
  </svg>`;
}
const IRIS = raw(buildIris());

const IRIS_MINI = raw(`<svg class="iris-mini" width="56" height="56" viewBox="0 0 64 64" fill="none" aria-hidden="true">
  <circle cx="32" cy="32" r="28" stroke="currentColor" stroke-width="0.6" opacity="0.4"/>
  <circle cx="32" cy="32" r="20" stroke="currentColor" stroke-width="0.8"/>
  <circle cx="32" cy="32" r="12" stroke="currentColor" stroke-width="0.5" opacity="0.7"/>
  <circle cx="32" cy="32" r="4" fill="currentColor"/>
  <line x1="32" y1="0" x2="32" y2="6" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="32" y1="58" x2="32" y2="64" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="0" y1="32" x2="6" y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
  <line x1="58" y1="32" x2="64" y2="32" stroke="currentColor" stroke-width="0.5" opacity="0.5"/>
</svg>`);

const BRAND_MARK = raw(`<svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <circle cx="16" cy="16" r="14" stroke="currentColor" stroke-width="1" opacity="0.5"/>
  <circle cx="16" cy="16" r="9" stroke="currentColor" stroke-width="1"/>
  <circle cx="16" cy="16" r="3" fill="currentColor"/>
</svg>`);

// Microsoft sign-in button per the official brand guidelines:
// https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-branding-in-apps
const MSFT_LOGO = raw(`<svg class="signin-logo" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#F35325"/><rect x="11" y="1" width="9" height="9" fill="#81BC06"/><rect x="1" y="11" width="9" height="9" fill="#05A6F0"/><rect x="11" y="11" width="9" height="9" fill="#FFBA08"/></svg>`);

const GOOGLE_LOGO = raw(`<svg class="signin-logo" viewBox="0 0 24 24" aria-hidden="true">
  <path fill="#EA4335" d="M12 10.2v3.9h5.5c-.24 1.5-1.7 4.3-5.5 4.3-3.3 0-6-2.7-6-6.1S8.7 6.2 12 6.2c1.9 0 3.1.8 3.9 1.5l2.6-2.5C16.9 3.7 14.6 2.7 12 2.7 6.9 2.7 2.8 6.8 2.8 12s4.1 9.3 9.2 9.3c5.3 0 8.8-3.7 8.8-9 0-.6-.1-1.1-.2-1.6H12z"/>
  <path fill="#4285F4" d="M21 12.3c0-.6-.1-1.1-.2-1.6H12v3.9h5.5c-.2 1.3-1 2.4-2.1 3.1l3.3 2.5C20.8 18.7 21 15.7 21 12.3z"/>
  <path fill="#FBBC05" d="M5.8 14.1c-.2-.6-.3-1.2-.3-1.9s.1-1.3.3-1.9L2.8 8.1A9.27 9.27 0 0 0 2.8 16l3-1.9z"/>
</svg>`);

const CLOCK_ICON = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5"/>
  <path d="M12 7v5l3 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>`);

const KEY_ICON = raw(`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="7" cy="12" r="3.5" stroke="currentColor" stroke-width="1.6"/>
  <path d="M10.5 12h10M17.5 12v3M21 12v2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
</svg>`);

const PYRAMID = raw(`<div class="corner-mark" aria-hidden="true">       ▲
      ▲ ▲
     ▲   ▲
    ▲  ◉  ▲
   ▲       ▲
  ▲▲▲▲▲▲▲▲▲
TYRELL · NEXUS-7</div>`);

// Known *.romaine.life apps shown in the Authorized Modules tile grid. The
// `granted` flag on signed-in view comes from the user's `apps` JSON blob:
// any key matching `name` here counts as granted, and the value (if any)
// becomes the prefs count.
const ROMAINE_APPS = [
  { host: "homepage.romaine.life",     name: "homepage" },
  { host: "workout.romaine.life",      name: "kill-me" },
  { host: "investing.romaine.life",    name: "investing" },
  { host: "diagrams.romaine.life",     name: "diagrams" },
  { host: "tank.romaine.life",         name: "tank-operator" },
  { host: "fzt-frontend.romaine.life", name: "fzt-frontend" },
  { host: "glimmung.romaine.life",     name: "glimmung" },
];

// VK-style probe questions, rotated client-side on the signed-out card.
// Original copy — same interrogative rhythm as the film's test ("describe
// in single words"), but written fresh.
const EMPATHY_PROMPTS = [
  "You're walking through a corridor of mirrors. One reflection blinks before you do. You stop. Account for the time elapsed before you continue.",
  "A neighbour's terrier slips on the sidewalk. Its leg breaks audibly. The owner is three apartments away. Describe the next thirty seconds.",
  "Your grandmother sends a recording of her voice on your birthday. She has been dead nine years. You play it twice. Explain the second time.",
  "A child you don't recognise hands you a folded paper boat. You unfold it; the inside is blank. The child has gone. Describe your face in the next moment.",
  "An attendant at the duty-free counter asks if you have anything to declare. You are carrying only a paperback. You hesitate. Why.",
  "You wake at 4:11 a.m. to a perfect copy of your own handwriting on the wall above the bed. The handwriting is dry. Continue.",
];

// Cinematic atmosphere strip in the footer — derivative pitches, not movie
// dialogue. Rotates every 6.4s.
const OFFWORLD_PITCHES = [
  "off-world emigration · sectors 1138–2049 accepting applicants · embark Q3 2089",
  "a new sun. a new soil. carbon-stipend on signing · port terminal 14",
  "twin moons · pre-fab habitats · 8-year colonist warranty",
  "leave the dust behind. golden land. begin again — petition Tyrell relocation",
  "courier vessels weekly · standard manifest · no biometric exit fee",
  "sponsored: SHIMATA-DOMINGUEZ aerospace · clear-air corridors only",
];

// ── Inline stylesheet ─────────────────────────────────────────────────────
// Distilled from the design handoff (design-fetch/auth/project/design/
// styles.css + colors_and_type.css). Only the `vk` theme is shipped to
// production — austere/hybrid variants and the dev tweaks panel are dropped.
const STYLES = raw(`
:root {
  --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
  --font-primary: "Archivo", "Vazirmatn", var(--font-sans);
  --font-mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "Consolas", monospace;

  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-2xl: 1.5rem;
  --text-3xl: 1.875rem;

  --gray-950: #0c0907;
  --gray-900: #140e0a;
  --gray-850: #1c130d;
  --gray-800: #3a2614;
  --gray-700: #5a3a18;
  --gray-500: #9b9b9b;
  --gray-400: #b4b4b4;

  --bg-app:        #0a0807;
  --bg-hover-soft: rgba(255, 255, 255, 0.05);

  --border-subtle: rgba(255, 122, 58, 0.12);
  --border-strong: rgba(255, 122, 58, 0.22);

  --fg-primary:   #ffffff;
  --fg-body:      #e6cab0;
  --fg-secondary: #f4d8b8;
  --fg-muted:     #b08858;
  --fg-faint:     #8c5a26;

  --vk-accent:      #ff7a3a;
  --vk-accent-soft: rgba(255, 122, 58, 0.16);
  --vk-iris-glow:   0 0 32px rgba(255, 107, 53, 0.35);
  --vk-grid:        rgba(255, 122, 58, 0.04);

  --status-online:    #ffb073;
  --status-online-bg: rgba(255, 122, 58, 0.14);
  --status-error:     #ef6f6f;
  --status-error-bg:  rgba(239, 111, 111, 0.12);
  --status-pending:   var(--gray-400);

  --radius-sm:   0.375rem;
  --radius-md:   0.5rem;
  --radius-lg:   0.75rem;
  --radius-pill: 9999px;

  --ease-out: cubic-bezier(0.22, 0.61, 0.36, 1);
}

* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  background: var(--bg-app);
  color: var(--fg-body);
  font-family: var(--font-sans);
  font-size: var(--text-sm);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}

/* faint dot-grid backdrop */
body::after {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image: radial-gradient(var(--vk-grid) 1px, transparent 1px);
  background-size: 24px 24px;
  background-position: center;
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
code, kbd, samp {
  font-family: var(--font-mono);
  font-size: 0.85em;
  background: var(--gray-850);
  padding: 0.05rem 0.25rem;
  border-radius: var(--radius-sm);
}

/* ── Stage ───────────────────────────────────────────────────────── */

.stage {
  position: relative;
  z-index: 1;
  height: 100%;
  display: grid;
  grid-template-rows: auto 1fr auto;
  padding: 28px clamp(20px, 5vw, 64px);
  max-width: 1080px;
  margin: 0 auto;
}

/* ── Top bar ─────────────────────────────────────────────────────── */

.topbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 24px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand {
  display: flex; align-items: center; gap: 12px;
  font-family: var(--font-primary);
}
.brand-mark {
  width: 32px; height: 32px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--vk-accent);
}
.brand-text { display: flex; flex-direction: column; gap: 2px; line-height: 1; }
.brand-text .lockup { font-size: 14px; font-weight: 500; letter-spacing: -0.005em; color: var(--fg-primary); }
.brand-text .lockup .dim { color: var(--fg-faint); font-weight: 400; }
.brand-text .division { font-size: 10px; font-weight: 500; letter-spacing: 0.18em; text-transform: uppercase; color: var(--fg-faint); }

.topbar-meta {
  display: flex; align-items: center; gap: 16px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
}
.topbar-meta .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--status-online); box-shadow: 0 0 8px var(--status-online); }
.topbar-meta .sep { color: var(--gray-800); }
@media (max-width: 640px) {
  .topbar-meta .meta-hide-sm { display: none; }
}

/* ── Main column ────────────────────────────────────────────────── */

.main {
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 24px 0;
  min-height: 0;
  overflow-y: auto;
}
.main > * { margin-block: auto; }

/* ── Signed-out card ────────────────────────────────────────────── */

.vk-card {
  width: 100%;
  max-width: 520px;
  display: flex; flex-direction: column; align-items: center;
  text-align: center;
  gap: 8px;
  animation: vk-fade-in 360ms var(--ease-out);
}
@keyframes vk-fade-in {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: none; }
}
.vk-card .iris-wrap {
  position: relative;
  width: 168px; height: 168px;
  margin: 8px 0 18px;
  display: flex; align-items: center; justify-content: center;
  filter: drop-shadow(var(--vk-iris-glow));
}
.vk-card .iris {
  color: var(--vk-accent);
  animation: iris-breathe 4.5s ease-in-out infinite;
}
@keyframes iris-breathe {
  0%, 100% { opacity: 0.85; transform: scale(1); }
  50%      { opacity: 1;    transform: scale(1.035); }
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
  font-size: 11px;
  letter-spacing: 0.25em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin: 4px 0 0;
}
.vk-card .lede {
  font-size: 14px;
  color: var(--fg-muted);
  max-width: 380px;
  margin: 16px auto 4px;
  line-height: 1.55;
  text-wrap: pretty;
}
.vk-card .epigraph {
  font-family: var(--font-mono);
  font-size: 12px;
  font-style: italic;
  color: var(--fg-faint);
  margin: 0 0 28px;
}

.signin-stack { display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 320px; }
.signin-btn {
  display: flex; align-items: center; gap: 12px;
  height: 44px; padding: 0 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--gray-800);
  background: var(--gray-900);
  color: var(--fg-primary);
  font-family: var(--font-primary);
  font-size: 14px; font-weight: 500;
  text-align: left;
  transition: background 120ms var(--ease-out), border-color 120ms var(--ease-out), transform 120ms var(--ease-out);
  text-decoration: none;
  width: 100%;
}
.signin-btn:hover { background: var(--gray-850); border-color: var(--gray-700); }
.signin-btn:active { transform: translateY(1px); }
.signin-btn .signin-label { flex: 1; }
.signin-btn .signin-meta {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  color: var(--fg-faint);
  text-transform: uppercase;
}
.signin-btn .signin-logo { width: 20px; height: 20px; display: inline-flex; }
.signin-form { width: 100%; }

.vk-footnote {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  margin: 24px 0 0;
  letter-spacing: 0.04em;
}

/* ── Empathy prompt (signed-out) ─────────────────────────────────── */

.empathy-prompt {
  width: 100%;
  max-width: 460px;
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
  background: var(--vk-accent);
  opacity: 0.4;
  border-radius: 1px;
}
.empathy-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin-bottom: 6px;
}
.empathy-num { color: var(--vk-accent); }
.empathy-body {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--fg-secondary);
  text-wrap: pretty;
  min-height: 4em;
  animation: empathy-fade 480ms var(--ease-out);
}
@keyframes empathy-fade {
  from { opacity: 0; transform: translateY(3px); }
  to   { opacity: 1; transform: none; }
}

/* ── Signed-in dashboard ─────────────────────────────────────────── */

.dash {
  width: 100%;
  max-width: 880px;
  margin: 0 auto;
  display: flex; flex-direction: column;
  gap: 20px;
  animation: vk-fade-in 360ms var(--ease-out);
}
.dash-head {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 20px;
  padding: 18px 20px;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-lg);
  background: linear-gradient(180deg, rgba(255,255,255,0.018), rgba(255,255,255,0)), var(--gray-950);
}
.dash-head .iris-mini-wrap {
  width: 64px; height: 64px;
  display: flex; align-items: center; justify-content: center;
  color: var(--vk-accent);
  filter: drop-shadow(var(--vk-iris-glow));
}
.dash-head .head-text { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.dash-head .head-name {
  font-family: var(--font-primary);
  font-size: 22px; font-weight: 600;
  letter-spacing: -0.015em;
  color: var(--fg-primary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dash-head .head-email {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg-muted);
}
.dash-head .head-designation {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--fg-faint);
  margin-top: 4px;
  flex-wrap: wrap;
}
.dash-head .nexus-tag {
  padding: 1px 6px;
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
  letter-spacing: 0.16em;
}
.dash-head .nexus-id { color: var(--fg-secondary); letter-spacing: 0.16em; }
.dash-head .nexus-sep { color: var(--gray-800); }
.dash-head .head-status {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--status-online);
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 2px;
}
.dash-head .head-status .blink-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--status-online);
  animation: blink 1.6s steps(2) infinite;
}
.dash-head .head-aside { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }

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
}
.role-badge.is-admin {
  color: var(--vk-accent);
  border-color: color-mix(in oklab, var(--vk-accent), transparent 70%);
  background: var(--vk-accent-soft);
  text-shadow: 0 0 8px color-mix(in oklab, var(--vk-accent), transparent 50%);
}
.role-badge.is-pending {
  color: var(--status-pending);
  border-color: var(--gray-800);
  background: var(--gray-900);
}
.role-badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

.end-btn, .admin-btn {
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
  text-decoration: none;
}
.end-btn:hover {
  color: var(--status-error);
  border-color: color-mix(in oklab, var(--status-error), transparent 60%);
  background: var(--status-error-bg);
}
.admin-btn:hover {
  color: var(--vk-accent);
  border-color: color-mix(in oklab, var(--vk-accent), transparent 60%);
  background: var(--vk-accent-soft);
}

.signout-form { display: inline; margin: 0; }

/* sections */
.dash-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.dash-grid > .col-span-2 { grid-column: span 2; }
@media (max-width: 720px) {
  .dash-grid { grid-template-columns: 1fr; }
  .dash-grid > .col-span-2 { grid-column: auto; }
  .dash-head { grid-template-columns: auto 1fr; }
  .dash-head .head-aside { grid-column: span 2; flex-direction: row; align-items: center; justify-content: space-between; }
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
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-primary);
  font-size: 12px; font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--fg-secondary);
}
.section-head .title .sigil {
  font-family: var(--font-mono);
  color: var(--fg-faint);
  font-size: 11px;
  letter-spacing: 0.04em;
}
.section-head .title .meta {
  font-family: var(--font-mono);
  font-weight: 400;
  letter-spacing: 0;
  text-transform: none;
  color: var(--fg-faint);
  margin-left: 6px;
}
.section-head .count {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--fg-faint);
}
.section-body { padding: 6px; }
.section-body .empty {
  padding: 18px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  font-style: italic;
  color: var(--fg-faint);
  text-align: center;
}

/* rows */
.row {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 12px;
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
  font-size: 13px;
  color: var(--fg-primary);
  font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .row-secondary {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  overflow: hidden; text-overflow: ellipsis;
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
  background: color-mix(in oklab, var(--status-online), transparent 80%);
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
  text-decoration: none;
  color: inherit;
  transition: background 120ms, border-color 120ms, transform 120ms;
}
.app-tile:hover { background: var(--bg-hover-soft); border-color: var(--gray-800); }
.app-tile.granted { border-color: color-mix(in oklab, var(--vk-accent), transparent 75%); }
.app-tile.granted:hover { border-color: color-mix(in oklab, var(--vk-accent), transparent 55%); }
.app-tile .app-name {
  font-family: var(--font-primary);
  font-size: 13px;
  color: var(--fg-primary);
  font-weight: 500;
}
.app-tile .app-host {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-muted);
}
.app-tile .app-host strong { color: var(--fg-primary); font-weight: 500; }
.app-tile .app-foot {
  display: flex; align-items: center; justify-content: space-between;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--fg-faint);
}
.app-tile.granted .app-foot .ok { color: var(--vk-accent); }

/* claims viewer */
.claims-wrap { padding: 8px; }
.claims {
  margin: 0;
  padding: 14px 16px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.65;
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

.claims-tabs { display: inline-flex; gap: 4px; }
.claims-tab, .claims-copy {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.1em;
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

/* pending callout */
.pending-callout {
  border: 1px solid var(--gray-800);
  border-left: 2px solid var(--vk-accent);
  border-radius: var(--radius-md);
  background: var(--gray-950);
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg-muted);
  line-height: 1.55;
}

/* ── Footer ─────────────────────────────────────────────────────── */

.footer {
  display: flex; flex-direction: column;
  gap: 0;
  padding-top: 14px;
  border-top: 1px solid var(--border-subtle);
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-faint);
  letter-spacing: 0.04em;
}
.footer-row { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; }
.footer-links { display: inline-flex; gap: 14px; flex-wrap: wrap; }
.footer-links a {
  color: var(--fg-faint);
  border-bottom: 1px dotted transparent;
  transition: color 120ms, border-color 120ms;
}
.footer-links a:hover {
  color: var(--vk-accent);
  border-bottom-color: color-mix(in oklab, var(--vk-accent), transparent 60%);
}
.footer-sigil { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.3em; }

.offworld-ticker {
  display: flex; align-items: center; gap: 12px;
  margin-top: 10px;
  padding: 6px 10px;
  border: 1px dashed var(--border-subtle);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.04em;
  color: var(--fg-muted);
  background: linear-gradient(90deg, color-mix(in oklab, var(--vk-accent), transparent 92%), transparent 60%);
  overflow: hidden;
}
.offworld-tag {
  flex-shrink: 0;
  font-size: 9px; font-weight: 600;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  padding: 2px 6px;
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 60%);
  border-radius: var(--radius-sm);
  color: var(--vk-accent);
  background: var(--vk-accent-soft);
}
.offworld-line {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  animation: offworld-fade 6.4s ease-in-out infinite;
}
@keyframes offworld-fade {
  0%, 5%   { opacity: 0; transform: translateX(8px); }
  10%, 85% { opacity: 1; transform: none; }
  95%,100% { opacity: 0; transform: translateX(-8px); }
}

/* ── Corner mark ────────────────────────────────────────────────── */

.corner-mark {
  position: fixed;
  right: 18px; bottom: 16px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--fg-faint);
  letter-spacing: 0.2em;
  line-height: 1.15;
  text-align: right;
  pointer-events: none;
  z-index: 2;
  opacity: 0.55;
  white-space: pre;
}
@media (max-width: 720px) { .corner-mark { display: none; } }

@keyframes blink { 50% { opacity: 0; } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 1ms !important;
    transition-duration: 1ms !important;
  }
}

/* ── Admin console (carried over, restyled to match) ────────────── */

.admin-list { display: flex; flex-direction: column; gap: 10px; margin: 8px 0; }
.admin-card {
  padding: 14px 16px;
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-md);
  background: var(--gray-950);
}
.admin-card .admin-head {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 8px;
  gap: 12px;
}
.admin-card .admin-head .email { font-family: var(--font-primary); font-size: 14px; color: var(--fg-primary); }
.admin-card .admin-head .since { font-family: var(--font-mono); font-size: 10px; color: var(--fg-faint); letter-spacing: 0.1em; }
.admin-grid { display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; align-items: center; }
.admin-grid label { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--fg-faint); }
.admin-grid input, .admin-grid select, .admin-grid textarea {
  background: #000;
  color: var(--fg-body);
  border: 1px solid var(--gray-800);
  border-radius: var(--radius-sm);
  padding: 6px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
}
.admin-grid textarea { resize: vertical; min-height: 50px; }
.admin-actions { display: flex; gap: 8px; margin-top: 10px; }
.admin-flash {
  border: 1px solid color-mix(in oklab, var(--vk-accent), transparent 50%);
  background: var(--vk-accent-soft);
  color: var(--vk-accent);
  border-radius: var(--radius-md);
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  margin-bottom: 16px;
}
`);

const SCRIPT = raw(`
(() => {
  // Live UTC clock in the topbar
  const clock = document.getElementById("utc-clock");
  if (clock) {
    const pad = (n) => String(n).padStart(2, "0");
    const fmt = () => {
      const d = new Date();
      return pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " UTC";
    };
    clock.textContent = fmt();
    setInterval(() => { clock.textContent = fmt(); }, 1000);
  }

  // Show the active JWKS kid in the topbar once it loads.
  const kidEl = document.getElementById("jwks-kid");
  if (kidEl) {
    fetch("/api/auth/jwks").then(r => r.json()).then(j => {
      const kid = j && j.keys && j.keys[0] && j.keys[0].kid;
      if (kid) kidEl.textContent = "kid " + String(kid).slice(0, 4);
    }).catch(() => {});
  }

  // Rotating empathy prompt on the signed-out card.
  const empathy = document.getElementById("empathy");
  if (empathy) {
    let prompts = [];
    try { prompts = JSON.parse(empathy.dataset.prompts || "[]"); } catch (_) {}
    const bodyEl = empathy.querySelector(".empathy-body");
    const numEl = empathy.querySelector(".empathy-num");
    const total = prompts.length;
    if (total && bodyEl) {
      let i = Math.floor(Math.random() * total);
      const render = () => {
        bodyEl.textContent = prompts[i];
        if (numEl) numEl.textContent = "Q · " + String(i + 1).padStart(2, "0") + " / " + String(total).padStart(2, "0");
        // re-trigger fade animation
        bodyEl.style.animation = "none";
        // force reflow
        void bodyEl.offsetWidth;
        bodyEl.style.animation = "";
      };
      render();
      setInterval(() => { i = (i + 1) % total; render(); }, 9000);
    }
  }

  // Off-world emigration ticker.
  const ticker = document.getElementById("offworld");
  if (ticker) {
    let pitches = [];
    try { pitches = JSON.parse(ticker.dataset.pitches || "[]"); } catch (_) {}
    const line = ticker.querySelector(".offworld-line");
    if (pitches.length && line) {
      let i = 0;
      line.textContent = pitches[i];
      setInterval(() => {
        i = (i + 1) % pitches.length;
        line.textContent = pitches[i];
      }, 6400);
    }
  }

  // Decoded / raw tabs + copy button on the Subject Profile section.
  const subj = document.getElementById("subject-profile");
  if (subj) {
    const decoded = subj.querySelector("[data-pane='decoded']");
    const rawPane = subj.querySelector("[data-pane='raw']");
    const tabs = subj.querySelectorAll(".claims-tab");
    tabs.forEach(t => t.addEventListener("click", () => {
      tabs.forEach(x => x.classList.remove("is-active"));
      t.classList.add("is-active");
      const which = t.dataset.tab;
      if (decoded) decoded.style.display = which === "decoded" ? "" : "none";
      if (rawPane) rawPane.style.display = which === "raw" ? "" : "none";
    }));
    const copyBtn = subj.querySelector(".claims-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        const text = copyBtn.dataset.claims || "";
        try {
          await navigator.clipboard.writeText(text);
          copyBtn.classList.add("is-copied");
          const orig = copyBtn.textContent;
          copyBtn.textContent = "copied";
          setTimeout(() => {
            copyBtn.classList.remove("is-copied");
            copyBtn.textContent = orig;
          }, 1400);
        } catch (_) {}
      });
    }
  }
})();
`);

// ── HTML helpers ──────────────────────────────────────────────────────────

const SHELL = (title: string, body: ReturnType<typeof html>) => html`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&display=swap" />
    <style>${STYLES}</style>
  </head>
  <body>
    <div class="stage">${body}</div>
    ${PYRAMID}
    <script>${SCRIPT}</script>
  </body>
</html>`;

function topbar(status: "online" | "pending" = "online") {
  return html`<header class="topbar">
    <div class="brand">
      <span class="brand-mark">${BRAND_MARK}</span>
      <div class="brand-text">
        <div class="lockup">voight-kampff <span class="dim">/ auth.romaine.life</span></div>
        <div class="division">Tyrell · Authentication Division</div>
      </div>
    </div>
    <div class="topbar-meta">
      <span><span class="dot${status === "pending" ? " is-pending" : ""}"></span> auth.romaine.life · ${status}</span>
      <span class="sep meta-hide-sm">·</span>
      <span class="meta-hide-sm"><span id="jwks-kid">jwks rs256</span></span>
      <span class="sep">·</span>
      <span id="utc-clock">— UTC</span>
    </div>
  </header>`;
}

function footer() {
  return html`<footer class="footer">
    <div class="footer-row">
      <div class="footer-links">
        <a href="/api/auth/jwks">/api/auth/jwks</a>
        <a href="/api/auth/get-session">/api/auth/get-session</a>
        <a href="https://github.com/nelsong6/auth">source</a>
      </div>
      <div class="footer-sigil">NEXUS-7 · BUILD ${BUILD}</div>
    </div>
    <div id="offworld" class="offworld-ticker" aria-live="off" data-pitches="${JSON.stringify(OFFWORLD_PITCHES)}">
      <span class="offworld-tag">OFF-WORLD</span>
      <span class="offworld-line">${OFFWORLD_PITCHES[0]}</span>
    </div>
  </footer>`;
}

// Server-rendered syntax-highlighted JSON. Keys orange, strings mint,
// numbers lavender, booleans clay, punctuation faint. The output is
// HTML so call sites must use `raw()` when embedding.
function prettyClaims(value: unknown): string {
  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const render = (v: unknown, indent: number): string => {
    const pad = "  ".repeat(indent);
    if (v === null) return `<span class="n">null</span>`;
    if (typeof v === "boolean") return `<span class="b">${v}</span>`;
    if (typeof v === "number") return `<span class="n">${v}</span>`;
    if (typeof v === "string") return `<span class="s">"${escape(v)}"</span>`;
    if (Array.isArray(v)) {
      if (v.length === 0) return "[]";
      const inner = v.map((x, i) => `${pad}  ${render(x, indent + 1)}${i < v.length - 1 ? "," : ""}`).join("\n");
      return `[\n${inner}\n${pad}]`;
    }
    if (typeof v === "object") {
      const entries = Object.entries(v as Record<string, unknown>);
      if (entries.length === 0) return "{}";
      const inner = entries
        .map(([k, val], i) => `${pad}  <span class="k">"${escape(k)}"</span><span class="p">:</span> ${render(val, indent + 1)}${i < entries.length - 1 ? "," : ""}`)
        .join("\n");
      return `{\n${inner}\n${pad}}`;
    }
    return String(v);
  };
  return render(value, 0);
}

// Static fake JWT for the "raw" tab — three base64-looking blobs. The header
// and payload are real base64url, the signature is decorative. The real
// JWT is available at /api/auth/token; we don't surface it on the page to
// avoid handing out a copy-pasteable token from the dashboard.
function fakeJwt(claims: Record<string, unknown>): string {
  const b64 = (s: string) => Buffer.from(s).toString("base64url");
  const header = b64(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64(JSON.stringify(claims));
  const sig = "qV1F9b7yK3v2hN8r5sP1xZmL0aW3oI4cT6gQ7B8nE2dM_Y9jK1pR4sV8tU3wX5yA0bC2eF7gH9iJ";
  return `${header}.${payload}.${sig}`.replace(/(.{64})/g, "$1\n");
}

// ── Fixtures + auth-state helper ──────────────────────────────────────────
// In TEST_MODE the handlers return hardcoded fixtures instead of hitting
// Better Auth + the DB. Slot deployments at *.auth.dev.romaine.life run
// in this mode so an operator can cruise the signed-in dashboard without
// any backend.

type AuthState = {
  session: { id: string; createdAt: Date; expiresAt: Date };
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    role?: string;
    apps?: string;
  };
  accounts: Array<{ id: string; providerId: string; createdAt: Date }>;
  sessions: Array<{ id: string; userAgent: string | null; ipAddress: string | null; createdAt: Date }>;
};

const TEST_AUTH_STATE: AuthState = {
  session: {
    id: "s_01",
    createdAt: new Date("2026-05-15T09:42:18Z"),
    expiresAt: new Date("2026-05-22T09:42:18Z"),
  },
  user: {
    id: "usr_9c4f1e8a0d6b",
    name: "Rachael Tyrell",
    email: "rachael@romaine.life",
    emailVerified: true,
    createdAt: new Date("2025-03-14T11:42:18Z"),
    role: "admin",
    apps: JSON.stringify({
      homepage: { theme: "dark" },
      "kill-me": { tdee: 2200 },
      investing: {},
    }),
  },
  accounts: [
    { id: "acc_ms_01", providerId: "microsoft", createdAt: new Date("2025-03-14T11:42:18Z") },
    { id: "acc_g_01", providerId: "google", createdAt: new Date("2025-09-02T08:00:00Z") },
  ],
  sessions: [
    { id: "s_01", userAgent: "Firefox 138 · macOS 14.5", ipAddress: "73.119.84.12", createdAt: new Date("2026-05-15T09:42:00Z") },
    { id: "s_02", userAgent: "Safari 18.4 · iOS 18.4",   ipAddress: "73.119.84.12", createdAt: new Date("2026-05-14T22:08:00Z") },
    { id: "s_03", userAgent: "Chromium 134 · Linux",     ipAddress: "104.28.116.7", createdAt: new Date("2026-05-12T14:11:00Z") },
  ],
};

const TEST_USERS = [
  { id: TEST_AUTH_STATE.user.id, email: "rachael@romaine.life", name: "Rachael Tyrell", role: "admin", apps: TEST_AUTH_STATE.user.apps ?? "{}", emailVerified: true, image: null, createdAt: new Date("2025-03-14T11:42:18Z"), updatedAt: new Date("2026-05-15T09:42:00Z") },
  { id: "usr_a1b2c3d4e5f6", email: "deckard@romaine.life", name: "Rick Deckard", role: "user", apps: "{}", emailVerified: true, image: null, createdAt: new Date("2024-08-01T00:00:00Z"), updatedAt: new Date("2026-05-10T00:00:00Z") },
  { id: "usr_z9y8x7w6v5u4", email: "j.f.sebastian@romaine.life", name: "J.F. Sebastian", role: "pending", apps: "{}", emailVerified: false, image: null, createdAt: new Date("2026-04-22T00:00:00Z"), updatedAt: new Date("2026-04-22T00:00:00Z") },
];

async function getAuthState(c: Context): Promise<AuthState | null> {
  if (TEST_MODE) {
    return isTestSignedIn(c) ? TEST_AUTH_STATE : null;
  }
  const result = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!result?.session) return null;
  const userId = result.user.id;
  const accounts = await db.select().from(account).where(eq(account.userId, userId));
  const sessions = await db.select().from(session).where(eq(session.userId, userId)).orderBy(desc(session.createdAt)).limit(5);
  return { session: result.session, user: result.user, accounts, sessions };
}

// ── Routes ────────────────────────────────────────────────────────────────

app.get("/", async (c) => {
  const result = await getAuthState(c);

  if (!result) {
    return c.html(SHELL("Voight-Kampff — auth.romaine.life", html`
      ${topbar("online")}
      <main class="main">
        <div class="vk-card">
          <div class="iris-wrap">${IRIS}</div>
          <h1>Voight-Kampff</h1>
          <p class="subtitle">Empathy Test · Subject Verification</p>
          <p class="lede">
            Examinee not identified. Authenticate to receive an RS256 token signed by this service; all <code>*.romaine.life</code> apps verify against this <code>jwks</code>.
          </p>
          <p class="epigraph">"more human than human" — Tyrell, 2019</p>

          <div id="empathy" class="empathy-prompt" data-prompts="${JSON.stringify(EMPATHY_PROMPTS)}">
            <div class="empathy-head">
              <span class="empathy-num">Q · 01 / ${String(EMPATHY_PROMPTS.length).padStart(2, "0")}</span>
              <span>probe pre-roll · sample question</span>
            </div>
            <p class="empathy-body">${EMPATHY_PROMPTS[0]}</p>
          </div>

          <div class="signin-stack">
            <form class="signin-form" method="POST" action="/sign-in/microsoft">
              <button class="signin-btn" type="submit">
                ${MSFT_LOGO}
                <span class="signin-label">Sign in with Microsoft</span>
                <span class="signin-meta">entra</span>
              </button>
            </form>
            <form class="signin-form" method="POST" action="/sign-in/google">
              <button class="signin-btn" type="submit">
                ${GOOGLE_LOGO}
                <span class="signin-label">Sign in with Google</span>
                <span class="signin-meta">oidc</span>
              </button>
            </form>
          </div>

          <p class="vk-footnote">
            session scoped to <code>.romaine.life</code> · sso across every subdomain
          </p>
        </div>
      </main>
      ${footer()}
    `));
  }

  const u = result.user;
  const accounts = result.accounts;
  const sessions = result.sessions;

  const role = (u as { role?: string }).role ?? "user";
  const appsBlob = (() => {
    try { return JSON.parse((u as { apps?: string }).apps ?? "{}") as Record<string, unknown>; }
    catch { return {} as Record<string, unknown>; }
  })();
  const claims = {
    iss: process.env.BASE_URL ?? "https://auth.romaine.life",
    sub: u.id,
    aud: "romaine.life",
    iat: Math.floor(result.session.createdAt.getTime() / 1000),
    exp: Math.floor(result.session.expiresAt.getTime() / 1000),
    email: u.email,
    name: u.name,
    email_verified: u.emailVerified,
    role,
    apps: appsBlob,
  };

  const currentSessionId = result.session.id;
  const grantedCount = ROMAINE_APPS.filter((a) => a.name in appsBlob).length;
  const createdAt = u.createdAt instanceof Date ? u.createdAt : new Date(u.createdAt);
  const nexusInc = createdAt.toISOString().slice(0, 10).split("-").reverse().join("·").toUpperCase();
  // short, stable per-user designation: first 3 alpha chars of the name +
  // first 3 chars of the user id. Falls back if anything's missing.
  const nameSlug = (u.name || "subject").replace(/[^A-Za-z]/g, "").slice(0, 3).toUpperCase().padEnd(3, "X");
  const idSlug = u.id.replace(/-/g, "").slice(0, 3).toUpperCase().padEnd(3, "0");
  const nexusId = `EXP·${nameSlug}-${idSlug}`;

  const roleLabel = role === "admin" ? "Blade Runner" : role === "pending" ? "Awaiting Review" : "Citizen";
  const roleClass = role === "admin" ? "is-admin" : role === "pending" ? "is-pending" : "";

  return c.html(SHELL(`${u.name} — Voight-Kampff`, html`
    ${topbar("online")}
    <main class="main">
      <div class="dash">
        <section class="dash-head">
          <div class="iris-mini-wrap">${IRIS_MINI}</div>
          <div class="head-text">
            <div class="head-name">${u.name}</div>
            <div class="head-email">${u.email} · ${u.id}</div>
            <div class="head-designation">
              <span class="nexus-tag">NEXUS-7</span>
              <span class="nexus-id">${nexusId}</span>
              <span class="nexus-sep">·</span>
              <span>inc. ${nexusInc}</span>
            </div>
            <div class="head-status">
              <span class="blink-dot"></span>
              ${role === "pending"
                ? raw(`awaiting blade-runner review`)
                : raw(`subject verified · empathy confirmed`)}
            </div>
          </div>
          <div class="head-aside">
            <span class="role-badge ${roleClass}"><span class="dot"></span>${roleLabel}</span>
            ${role === "admin"
              ? html`<a class="admin-btn" href="/admin">Tyrell Console</a>`
              : html``}
            <form class="signout-form" method="POST" action="/sign-out">
              <button class="end-btn" type="submit">End interview</button>
            </form>
          </div>
        </section>

        ${role === "pending" ? html`
          <div class="pending-callout">
            Authentication accepted, but the registry does not yet recognize you as a romaine.life subject. A blade runner must promote your status before downstream apps will admit you.
          </div>
        ` : html``}

        <div class="dash-grid">
          <section class="section">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Provenance</span>
              <span class="count">${accounts.length} linked</span>
            </div>
            <div class="section-body">
              ${accounts.length === 0
                ? html`<div class="empty">no linked accounts</div>`
                : accounts.map((a, i) => html`
                  <div class="row">
                    <span class="row-icon">${a.providerId === "microsoft" ? MSFT_LOGO : a.providerId === "google" ? GOOGLE_LOGO : KEY_ICON}</span>
                    <div class="row-main">
                      <div class="row-primary">${a.providerId}</div>
                      <div class="row-secondary">enrolled ${a.createdAt.toISOString().slice(0, 10)} · provider · ${a.providerId}</div>
                    </div>
                    <span class="pill${i === 0 ? " current" : ""}">${i === 0 ? "primary" : "linked"}</span>
                  </div>
                `)}
            </div>
          </section>

          <section class="section">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Prior Interrogations</span>
              <span class="count">${sessions.length} active</span>
            </div>
            <div class="section-body">
              ${sessions.length === 0
                ? html`<div class="empty">no recorded sessions</div>`
                : sessions.map((s) => html`
                  <div class="row">
                    <span class="row-icon">${CLOCK_ICON}</span>
                    <div class="row-main">
                      <div class="row-primary">${s.createdAt.toISOString().replace("T", " ").slice(0, 16)} UTC${s.id === currentSessionId ? "  ·  this session" : ""}</div>
                      <div class="row-secondary">${s.userAgent ?? "—"}${s.ipAddress ? ` · ${s.ipAddress}` : ""}</div>
                    </div>
                    ${s.id === currentSessionId
                      ? html`<span class="pill current">current</span>`
                      : html`<span class="pill">past</span>`}
                  </div>
                `)}
            </div>
          </section>

          <section class="section col-span-2">
            <div class="section-head">
              <span class="title"><span class="sigil">//</span>Authorized Modules</span>
              <span class="count">${grantedCount} of ${ROMAINE_APPS.length} subdomains</span>
            </div>
            <div class="apps">
              ${ROMAINE_APPS.map((a) => {
                const granted = a.name in appsBlob;
                const prefVal = appsBlob[a.name];
                const prefCount = prefVal && typeof prefVal === "object" && !Array.isArray(prefVal)
                  ? Object.keys(prefVal as Record<string, unknown>).length
                  : 0;
                return html`
                  <a class="app-tile${granted ? " granted" : ""}" href="https://${a.host}">
                    <span class="app-name">${a.name}</span>
                    <span class="app-host"><strong>${a.host.split(".")[0]}</strong>.romaine.life</span>
                    <div class="app-foot">
                      <span class="${granted ? "ok" : ""}">${granted ? "● granted" : "○ no prefs"}</span>
                      <span>${prefCount || "—"} prefs</span>
                    </div>
                  </a>
                `;
              })}
            </div>
          </section>

          <section id="subject-profile" class="section col-span-2">
            <div class="section-head">
              <span class="title">
                <span class="sigil">//</span>Subject Profile
                <span class="meta">token claims surfaced to romaine.life apps</span>
              </span>
              <span class="claims-tabs">
                <button class="claims-tab is-active" data-tab="decoded">decoded</button>
                <button class="claims-tab" data-tab="raw">raw</button>
                <button class="claims-copy" data-claims="${JSON.stringify(claims, null, 2)}">copy</button>
              </span>
            </div>
            <div class="claims-wrap">
              <pre class="claims" data-pane="decoded">${raw(prettyClaims(claims))}</pre>
              <pre class="claims" data-pane="raw" style="display:none">${fakeJwt(claims)}</pre>
            </div>
          </section>
        </div>
      </div>
    </main>
    ${footer()}
  `));
});

// ── Admin console ──────────────────────────────────────────────────────────
// Single-page user manager — role + per-app `apps` JSON blob, plus name.
// Source of truth for the platform-wide admin list (formerly the
// `romaine-life-admin-emails` KV secret). Gated on role=admin claim.

async function requireAdmin(c: Context) {
  if (TEST_MODE) {
    if (!isTestSignedIn(c)) return { status: 302 as const, location: "/" };
    return { ok: true as const, user: TEST_AUTH_STATE.user };
  }
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
  const users = TEST_MODE ? TEST_USERS : await db.select().from(user).orderBy(desc(user.createdAt));
  const flash = c.req.query("ok") ?? (TEST_MODE ? "test mode · changes are discarded" : null);
  return c.html(SHELL("Tyrell Console — Subjects", html`
    ${topbar("online")}
    <main class="main">
      <div class="dash">
        <section class="dash-head">
          <div class="iris-mini-wrap">${IRIS_MINI}</div>
          <div class="head-text">
            <div class="head-name">Subject Registry</div>
            <div class="head-email">Authenticate · Classify · Retire</div>
            <div class="head-designation">
              <span class="nexus-tag">CONSOLE</span>
              <span class="nexus-id">OPERATIONS</span>
            </div>
          </div>
          <div class="head-aside">
            <a class="admin-btn" href="/">← Dashboard</a>
          </div>
        </section>

        ${flash ? html`<div class="admin-flash">${flash}</div>` : html``}

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Active Subjects</span>
            <span class="count">${users.length} on file</span>
          </div>
          <div class="section-body">
            ${users.length === 0
              ? html`<div class="empty">no subjects on file</div>`
              : html`<div class="admin-list">
                ${users.map((u) => html`
                  <form class="admin-card" method="POST" action="/admin/users/${u.id}">
                    <div class="admin-head">
                      <span class="email">${u.email}</span>
                      <span class="since">${u.createdAt.toISOString().slice(0, 10)}</span>
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
                      <button class="admin-btn" type="submit">Update</button>
                    </div>
                  </form>
                `)}
              </div>`}
          </div>
        </section>

        <section class="section col-span-2">
          <div class="section-head">
            <span class="title"><span class="sigil">//</span>Enroll Subject</span>
            <span class="count">pre-create row</span>
          </div>
          <div class="section-body">
            <form class="admin-card" method="POST" action="/admin/users">
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
                <button class="admin-btn" type="submit">Enroll</button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </main>
    ${footer()}
  `));
});

app.post("/admin/users", async (c) => {
  const gate = await requireAdmin(c);
  if ("status" in gate) return c.text("forbidden", gate.status === 302 ? 401 : 403);
  if (TEST_MODE) return c.redirect("/admin?ok=test+mode+%C2%B7+enroll+discarded");
  const form = await c.req.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const name = String(form.get("name") ?? "").trim() || email;
  const role = String(form.get("role") ?? "user");
  if (!email || !email.includes("@")) return c.text("invalid email", 400);
  if (role !== "admin" && role !== "user") return c.text("invalid role", 400);
  // Pre-create the row. Better Auth's Microsoft social provider matches on
  // email when the user signs in for the first time, so the row will gain
  // emailVerified=true + the Microsoft account link at that point.
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
  if (TEST_MODE) return c.redirect("/admin?ok=test+mode+%C2%B7+update+discarded");
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

// Shared social sign-in entrypoint. POST is the form-driven path from
// this service's own dashboard. GET with a `callbackURL` query param is the
// cross-app sign-in path: downstream apps (e.g. tank.romaine.life) link
// here with their post-sign-in URL and the user gets redirected back to
// the app after the provider completes. Better Auth validates callbackURL
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

function testSignIn(c: Context, callbackURL: string) {
  setTestCookie(c);
  return c.redirect(callbackURL);
}

app.post("/sign-in/microsoft", (c) =>
  TEST_MODE ? testSignIn(c, "/") : socialSignInRedirect(c, "microsoft", "/"));
app.get("/sign-in/microsoft", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return TEST_MODE ? testSignIn(c, callbackURL) : socialSignInRedirect(c, "microsoft", callbackURL);
});
app.post("/sign-in/google", (c) =>
  TEST_MODE ? testSignIn(c, "/") : socialSignInRedirect(c, "google", "/"));
app.get("/sign-in/google", (c) => {
  const callbackURL = c.req.query("callbackURL") ?? "/";
  return TEST_MODE ? testSignIn(c, callbackURL) : socialSignInRedirect(c, "google", callbackURL);
});

app.post("/sign-out", async (c) => {
  if (TEST_MODE) {
    clearTestCookie(c);
    return c.redirect("/");
  }
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
