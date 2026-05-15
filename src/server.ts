import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import { auth } from "./auth.js";

const app = new Hono();
app.use("*", logger());

app.get("/health", (c) => c.text("ok"));
app.get("/ready", (c) => c.text("ok"));

// Mount Better Auth at /api/auth/*. Handles sign-in flows, JWKS, sessions, etc.
app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`auth listening on :${info.port}`);
});
