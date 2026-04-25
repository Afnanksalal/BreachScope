import { randomBytes } from "crypto";
import { hashApiKey } from "./crypto";

const KEY_PREFIX = "bs_live_";
const DISPLAY_PREFIX_LEN = KEY_PREFIX.length + 8;

export interface GeneratedKey {
  /** Shown ONCE at creation — never stored */
  fullKey: string;
  /** First 16 chars — safe to display in the UI */
  prefix: string;
  /** SHA-256 of fullKey — stored in the DB */
  hash: string;
}

export function generateApiKey(): GeneratedKey {
  const raw = randomBytes(32).toString("base64url");
  const fullKey = `${KEY_PREFIX}${raw}`;
  const prefix = fullKey.slice(0, DISPLAY_PREFIX_LEN);
  const hash = hashApiKey(fullKey);
  return { fullKey, prefix, hash };
}

export function verifyApiKey(submitted: string, storedHash: string): boolean {
  return hashApiKey(submitted) === storedHash;
}
