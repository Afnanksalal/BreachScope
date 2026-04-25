import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/auth.js", () => ({
  loadCredentials: vi.fn(),
}));

vi.mock("../../src/core/logger.js", () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn() },
}));

import { loadCredentials } from "../../src/core/auth.js";
import { fetchRemoteConfig, clearRemoteConfigCache } from "../../src/core/remote-config.js";

const mockLoadCredentials = vi.mocked(loadCredentials);

const VALID_CREDS = {
  token: "bs_live_testtoken",
  dashboardUrl: "https://app.breachscope.com",
  savedAt: "2026-04-25T00:00:00.000Z",
};

const VALID_CONFIG = {
  openaiKey: null,
  firecrawlKey: null,
  defaultMode: "basic",
  defaultScanMode: "all",
};

beforeEach(() => {
  vi.clearAllMocks();
  clearRemoteConfigCache();
  vi.stubGlobal("fetch", vi.fn());
});

describe("fetchRemoteConfig", () => {
  it("returns null when no credentials saved", async () => {
    mockLoadCredentials.mockReturnValue(null);
    const result = await fetchRemoteConfig();
    expect(result).toBeNull();
  });

  it("fetches config with Authorization header", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => VALID_CONFIG,
    } as Response);

    await fetchRemoteConfig();

    expect(fetch).toHaveBeenCalledWith(
      `${VALID_CREDS.dashboardUrl}/api/cli/config`,
      { headers: { Authorization: `Bearer ${VALID_CREDS.token}` } },
    );
  });

  it("returns parsed config on success", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => VALID_CONFIG,
    } as Response);

    const result = await fetchRemoteConfig();
    expect(result).toMatchObject({
      defaultMode: "basic",
      defaultScanMode: "all",
    });
  });

  it("caches result and does not fetch twice", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => VALID_CONFIG,
    } as Response);

    await fetchRemoteConfig();
    await fetchRemoteConfig();

    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("clears cache after clearRemoteConfigCache()", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => VALID_CONFIG,
    } as Response);

    await fetchRemoteConfig();
    clearRemoteConfigCache();
    await fetchRemoteConfig();

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returns null on 401 response", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 401,
    } as Response);

    const result = await fetchRemoteConfig();
    expect(result).toBeNull();
  });

  it("returns null on non-OK response", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 500,
    } as Response);

    const result = await fetchRemoteConfig();
    expect(result).toBeNull();
  });

  it("returns null when response does not match RemoteConfig shape", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ unexpectedField: true }),
    } as Response);

    const result = await fetchRemoteConfig();
    expect(result).toBeNull();
  });

  it("returns null when fetch throws (network error)", async () => {
    mockLoadCredentials.mockReturnValue(VALID_CREDS);
    vi.mocked(fetch).mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await fetchRemoteConfig();
    expect(result).toBeNull();
  });
});
