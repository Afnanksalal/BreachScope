import fs from "fs";
import path from "path";
import os from "os";

const CONFIG_DIR = path.join(os.homedir(), ".config", "breachscope");
const CREDS_FILE = path.join(CONFIG_DIR, "credentials.json");

interface Credentials {
  token: string;
  dashboardUrl: string;
  savedAt: string;
}

function ensureDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export function saveCredentials(token: string, dashboardUrl: string) {
  ensureDir();
  const creds: Credentials = { token, dashboardUrl, savedAt: new Date().toISOString() };
  fs.writeFileSync(CREDS_FILE, JSON.stringify(creds, null, 2), { mode: 0o600 });
}

export function loadCredentials(): Credentials | null {
  try {
    if (!fs.existsSync(CREDS_FILE)) return null;
    const raw = fs.readFileSync(CREDS_FILE, "utf-8");
    return JSON.parse(raw) as Credentials;
  } catch {
    return null;
  }
}

export function clearCredentials() {
  if (fs.existsSync(CREDS_FILE)) {
    fs.unlinkSync(CREDS_FILE);
  }
}

export function isAuthenticated(): boolean {
  return loadCredentials() !== null;
}
