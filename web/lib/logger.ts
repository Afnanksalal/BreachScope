type LogLevel = "info" | "warn" | "error";

interface LogContext {
  requestId?: string;
  userId?: string;
  organizationId?: string | null;
  projectId?: string | null;
  scanId?: string | null;
  integrationId?: string | null;
  deliveryId?: string | null;
  provider?: string;
  [key: string]: unknown;
}

function write(level: LogLevel, event: string, context: LogContext = {}): void {
  const record = {
    level,
    event,
    ts: new Date().toISOString(),
    service: "breachscope-web",
    ...redact(context),
  };

  const line = JSON.stringify(record);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.info(line);
}

export const logger = {
  info: (event: string, context?: LogContext) => write("info", event, context),
  warn: (event: string, context?: LogContext) => write("warn", event, context),
  error: (event: string, context?: LogContext) => write("error", event, context),
};

function redact(context: LogContext): LogContext {
  return Object.fromEntries(
    Object.entries(context).map(([key, value]) => {
      if (/secret|token|password|key|authorization/i.test(key)) return [key, "[redacted]"];
      if (value instanceof Error) return [key, { name: value.name, message: value.message, stack: value.stack }];
      return [key, value];
    }),
  );
}
