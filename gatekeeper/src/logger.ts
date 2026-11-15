// Minimal structured logger. Only whitelisted, non-sensitive fields are
// ever logged: task ids, decisions, reason codes, durations, job ids and
// statuses. NEVER log secrets, API keys, request/response bodies, or proofs.
export type LogLevel = "info" | "warn" | "error";

export interface LogFields {
  [key: string]: string | number | boolean | undefined;
}

export function log(level: LogLevel, msg: string, fields: LogFields = {}): void {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  };
  const line = JSON.stringify(entry);
  if (level === "error") process.stderr.write(line + "\n");
  else process.stdout.write(line + "\n");
}

export const info = (msg: string, fields?: LogFields) => log("info", msg, fields);
export const warn = (msg: string, fields?: LogFields) => log("warn", msg, fields);
export const error = (msg: string, fields?: LogFields) => log("error", msg, fields);
