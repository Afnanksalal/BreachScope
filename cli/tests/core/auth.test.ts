import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";

vi.mock("fs");

// os.homedir() is evaluated at module load time in auth.ts, so mock before import
vi.mock("os", () => {
  const MOCK_HOME = "/home/testuser";
  return {
    default: { homedir: () => MOCK_HOME, ...require("os") },
    homedir: () => MOCK_HOME,
  };
});

const mockFs = vi.mocked(fs);

// Derive the same paths the module computes
const CONFIG_DIR = path.join(os.homedir(), ".config", "breachscope");
const CREDS_FILE = path.join(CONFIG_DIR, "credentials.json");

function setupFs(fileExists: boolean, fileContent?: string) {
  // Use a broad match so tests work regardless of slash style on any OS
  mockFs.existsSync.mockImplementation(() => fileExists);
  mockFs.mkdirSync.mockImplementation(() => undefined);
  mockFs.writeFileSync.mockImplementation(() => undefined);
  mockFs.unlinkSync.mockImplementation(() => undefined);
  if (fileContent !== undefined) {
    mockFs.readFileSync.mockReturnValue(fileContent as never);
  } else {
    mockFs.readFileSync.mockImplementation(() => { throw new Error("ENOENT"); });
  }
}

beforeEach(() => {
  vi.clearAllMocks();
});

import { saveCredentials, loadCredentials, clearCredentials, isAuthenticated }
  from "../../src/core/auth.js";

// ─── saveCredentials ──────────────────────────────────────────────────────────

describe("saveCredentials", () => {
  it("writes credentials file with mode 0o600", () => {
    setupFs(false);
    saveCredentials("tok_abc", "https://app.breachscope.com");

    expect(mockFs.writeFileSync).toHaveBeenCalledWith(
      CREDS_FILE,
      expect.stringContaining('"token"'),
      { mode: 0o600 },
    );
    const raw = mockFs.writeFileSync.mock.calls[0]?.[1] as string;
    const data = JSON.parse(raw);
    expect(data.token).toBe("tok_abc");
    expect(data.dashboardUrl).toBe("https://app.breachscope.com");
    expect(typeof data.savedAt).toBe("string");
  });

  it("creates config directory when it does not exist", () => {
    setupFs(false);
    saveCredentials("tok_abc", "https://app.breachscope.com");
    expect(mockFs.mkdirSync).toHaveBeenCalledWith(CONFIG_DIR, { recursive: true });
  });

  it("does not call mkdirSync when config dir already exists", () => {
    setupFs(true, JSON.stringify({ token: "x", dashboardUrl: "y", savedAt: "z" }));
    saveCredentials("tok_new", "https://app.breachscope.com");
    expect(mockFs.mkdirSync).not.toHaveBeenCalled();
  });
});

// ─── loadCredentials ──────────────────────────────────────────────────────────

describe("loadCredentials", () => {
  it("returns null when credentials file does not exist", () => {
    setupFs(false);
    expect(loadCredentials()).toBeNull();
  });

  it("parses and returns stored credentials", () => {
    const stored = {
      token: "tok_live",
      dashboardUrl: "https://app.breachscope.com",
      savedAt: "2026-04-25T00:00:00.000Z",
    };
    setupFs(true, JSON.stringify(stored));
    const creds = loadCredentials();
    expect(creds).not.toBeNull();
    expect(creds?.token).toBe("tok_live");
    expect(creds?.dashboardUrl).toBe("https://app.breachscope.com");
  });

  it("returns null when file contains invalid JSON", () => {
    setupFs(true, "not-json{{{");
    expect(loadCredentials()).toBeNull();
  });

  it("returns null when readFileSync throws", () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockImplementation(() => { throw new Error("permission denied"); });
    expect(loadCredentials()).toBeNull();
  });
});

// ─── clearCredentials ─────────────────────────────────────────────────────────

describe("clearCredentials", () => {
  it("removes credentials file when it exists", () => {
    setupFs(true, "{}");
    clearCredentials();
    expect(mockFs.unlinkSync).toHaveBeenCalledWith(CREDS_FILE);
  });

  it("does nothing when file does not exist", () => {
    setupFs(false);
    clearCredentials();
    expect(mockFs.unlinkSync).not.toHaveBeenCalled();
  });
});

// ─── isAuthenticated ──────────────────────────────────────────────────────────

describe("isAuthenticated", () => {
  it("returns false when no credentials file exists", () => {
    setupFs(false);
    expect(isAuthenticated()).toBe(false);
  });

  it("returns true when valid credentials are stored", () => {
    const stored = {
      token: "tok_live",
      dashboardUrl: "https://app.breachscope.com",
      savedAt: "2026-04-25T00:00:00.000Z",
    };
    setupFs(true, JSON.stringify(stored));
    expect(isAuthenticated()).toBe(true);
  });

  it("returns false when stored file is corrupt JSON", () => {
    setupFs(true, "{{bad");
    expect(isAuthenticated()).toBe(false);
  });
});
