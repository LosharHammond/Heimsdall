import { redact } from "../shared/redact.js";

const order = { debug: 10, info: 20, warn: 30, error: 40 } as const;
type Level = keyof typeof order;
let threshold: number = order.info;

export function setLogLevel(l: Level) {
  threshold = order[l];
}
export let logSink: (line: string) => void = (l) => process.stdout.write(l + "\n");
export function setLogSink(fn: (line: string) => void) {
  logSink = fn;
}

/** Structured JSON logs. Fields are passed through the redactor, so secrets never reach logs. */
export function log(level: Level, msg: string, fields: Record<string, unknown> = {}) {
  if (order[level] < threshold) return;
  logSink(JSON.stringify({ t: new Date().toISOString(), level, msg, ...(redact(fields) as object) }));
}
