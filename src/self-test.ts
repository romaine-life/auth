import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

// The image's self-test: the built server's whole module graph loads in TEST_MODE (no database,
// no secrets), answers /health, and the image runs as the nodejs user (uid 1001), which owns
// every file under /app. Its result is the exit code.
process.env.TEST_MODE = "true";
process.env.SELF_TEST = "true";
process.env.BASE_URL ??= "http://127.0.0.1:3000";
process.env.BETTER_AUTH_SECRET ??= randomBytes(32).toString("hex");

function foreignOwned(dir: string, uid: number): string | null {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (statSync(path).uid !== uid) return path;
    if (entry.isDirectory()) {
      const found = foreignOwned(path, uid);
      if (found) return found;
    }
  }
  return null;
}

try {
  const { app } = await import("./server.js");
  const health = await app.request("/health");
  if (health.status !== 200 || (await health.text()) !== "ok") throw new Error(`/health: HTTP ${health.status}`);
  // In the image only: a dev machine runs this as whoever it is.
  if (process.platform === "linux" && process.cwd() === "/app") {
    if (process.getuid?.() !== 1001) throw new Error(`runs as uid ${process.getuid?.()}, not nodejs (1001)`);
    const foreign = foreignOwned("/app", 1001);
    if (foreign) throw new Error(`${foreign} isn't owned by nodejs`);
  }
  console.log("auth self-test passed");
} catch (error) {
  console.error("auth self-test failed:", error);
  process.exitCode = 1;
}
