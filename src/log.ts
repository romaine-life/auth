// auth's log: the estate's one log line (romaine-life/logline, AHT-204) on stdout, which the
// cluster ships.
//
//   2026-11-26T14:02:11.408-08:00 pid=1 info request method=GET path=/health status=200 ms=1
//
// A message is fixed text; what varies goes in fields. auth handles credentials: a token,
// code, cookie, certificate or Authorization value is never passed to the log at all, and
// any text from outside auth (an error, an upstream body, a request path) goes through
// `outside` or `errorText`, which mask what looks like a credential.
import { Logger, redact } from "@romaine-life/logline";
import type { MiddlewareHandler } from "hono";

const stdout = Logger.stream(process.stdout);
type Level = "info" | "warn" | "error";

// A field whose value is undefined or null is left out, as JSON.stringify left it out of the
// lines before.
function present(fields: Record<string, unknown>): Array<[string, unknown]> {
  return Object.entries(fields).filter(([, value]) => value !== undefined && value !== null);
}

export const log = {
  log(level: Level, message: string, fields: Record<string, unknown> = {}): void {
    stdout.log(level, message, present(fields));
  },
  info(message: string, fields?: Record<string, unknown>): void { log.log("info", message, fields); },
  warn(message: string, fields?: Record<string, unknown>): void { log.log("warn", message, fields); },
  error(message: string, fields?: Record<string, unknown>): void { log.log("error", message, fields); },
};

/** The most a field holding outside text keeps, so one upstream body can't flood the log. */
export const OUTSIDE_LIMIT = 4096;

/** Text from outside auth, masked and capped for a field. */
export function outside(text: unknown): string {
  const masked = redact(String(text));
  return masked.length > OUTSIDE_LIMIT ? `${masked.slice(0, OUTSIDE_LIMIT)}...` : masked;
}

/** An error for the `error` field: its stack (which starts with its message), masked. */
export function errorText(e: unknown): string {
  return outside(e instanceof Error ? (e.stack ?? `${e.name}: ${e.message}`) : e);
}

/** The status a request's line takes its level from: a server failure is an error. */
function requestLevel(status: number): "info" | "error" {
  return status >= 500 ? "error" : "info";
}

/**
 * One line per request, once it is answered: method, path, status and milliseconds. The path
 * is the URL's path alone: a query can carry a sign-in code, state or device code, so it is
 * never logged, and the path is masked as well.
 */
export function requestLog(): MiddlewareHandler {
  return async (c, next) => {
    const start = performance.now();
    try {
      await next();
    } finally {
      const status = c.res?.status ?? 500;
      log.log(requestLevel(status), "request", {
        method: c.req.method,
        path: outside(new URL(c.req.url).pathname),
        status,
        ms: Math.round(performance.now() - start),
      });
    }
  };
}

/**
 * Better Auth's logger option: its lines come here instead of its own colored format, at its
 * level (debug as info), its text masked as outside text.
 */
export const betterAuthLogger = {
  log(level: "debug" | "info" | "warn" | "error", message: string, ...args: unknown[]): void {
    log.log(level === "debug" ? "info" : level, "better-auth", {
      text: outside(message),
      detail: args.length ? outside(args.map((a) => (a instanceof Error ? errorText(a) : typeof a === "string" ? a : JSON.stringify(a))).join(" ")) : undefined,
    });
  },
};
