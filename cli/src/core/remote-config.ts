import { resolveCredentials } from "./auth.js";
import { logger } from "./logger.js";

export interface RemoteConfig {
  openaiKey: string | null;
  firecrawlKey: string | null;
  defaultMode: string;
  defaultScanMode: string;
  sandboxScanMode: string;
  sandboxDeep: boolean;
}

function isRemoteConfig(v: unknown): v is RemoteConfig {
  return (
    typeof v === "object" &&
    v !== null &&
    "defaultMode" in v &&
    "defaultScanMode" in v
  );
}

let cached: RemoteConfig | null = null;
const REMOTE_CONFIG_TIMEOUT_MS = 5000;

export async function fetchRemoteConfig(): Promise<RemoteConfig | null> {
  if (cached) return cached;

  const creds = resolveCredentials();
  if (!creds) return null;

  try {
    const res = await fetch(`${creds.dashboardUrl}/api/cli/config`, {
      headers: { Authorization: `Bearer ${creds.token}` },
      signal: AbortSignal.timeout(REMOTE_CONFIG_TIMEOUT_MS),
    });

    if (!res.ok) {
      if (res.status === 401) {
        logger.warn("API key rejected — run `breachscope login` to re-authenticate.");
      }
      return null;
    }

    const data: unknown = await res.json();
    if (!isRemoteConfig(data)) {
      logger.warn("Unexpected response from dashboard config endpoint.");
      return null;
    }

    cached = data;
    return cached;
  } catch {
    logger.warn("Could not reach dashboard — using local environment variables if set.");
    return null;
  }
}

export function clearRemoteConfigCache(): void {
  cached = null;
}

export async function syncRemoteConfig(mode: string, scanMode: string): Promise<void> {
  const creds = resolveCredentials();
  if (!creds) return;

  try {
    await fetch(`${creds.dashboardUrl}/api/cli/config`, {
      method:  "PATCH",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${creds.token}`,
      },
      body: JSON.stringify({ defaultMode: mode, defaultScanMode: scanMode }),
      signal: AbortSignal.timeout(REMOTE_CONFIG_TIMEOUT_MS),
    });
  } catch {
    // fire-and-forget — never block a scan over this
  }
}
