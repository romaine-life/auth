// Types for @romaine-life/logline (romaine-life/logline js/logline.mjs), which ships none.
declare module "@romaine-life/logline" {
  export type Level = "info" | "warn" | "error";
  /** An object, or [key, value] pairs; a value is written with String(). */
  export type Fields = Record<string, unknown> | ReadonlyArray<readonly [string, unknown]>;

  export class Logger {
    constructor(options?: { path?: string | null; stream?: { write(line: string): unknown } | null; now?: () => Date });
    static open(app: string, overrideVar?: string): Logger;
    static file(file: string): Logger;
    static stream(stream?: { write(line: string): unknown }): Logger;
    readonly path: string | null;
    info(message: string, fields?: Fields): void;
    warn(message: string, fields?: Fields): void;
    error(message: string, fields?: Fields): void;
    log(level: Level, message: string, fields?: Fields): void;
  }

  export interface Entry {
    time: Date;
    offset: number;
    pid: number;
    level: Level;
    message: string;
    fields: Array<[string, string]>;
  }

  export const levels: readonly Level[];
  export const LIMIT: number;
  export const MARKER: string;
  export function format(time: Date, pid: number, level: Level, message: string, fields?: Fields, offset?: number): string;
  export function formatTime(date: Date, offset?: number): string;
  export function parse(line: string): Entry;
  export function redact(text: string): string;
}
