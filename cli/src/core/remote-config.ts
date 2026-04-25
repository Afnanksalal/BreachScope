import { loadCredentials } from "./auth.js";
import { logger } from "./logger.js";

export interface RemoteConfig {
  openaiKey: string | null;
  firecrawlKey: string | null;
  defaultMode: string;
  defaultScanMode: string;
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

export async function fetchRemoteConfig(): Promise<RemoteConfig | null> {
  if (cached) return cached;

  const creds = loadCredentials();
  if (!creds) return null;

  try {
    const res = await fetch(`${creds.dashboardUrl}/api/cli/config`, {
      headers: { Authorization: `Bearer ${creds.token}` },
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
