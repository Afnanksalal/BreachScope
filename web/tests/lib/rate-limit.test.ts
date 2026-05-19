import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearRateLimitsForTests, rateLimit } from "@/lib/rate-limit";

describe("rateLimit", () => {
  beforeEach(() => {
    clearRateLimitsForTests();
    vi.unstubAllEnvs();
  });

  it("allows requests below the limit and blocks after the limit", async () => {
    await expect(rateLimit("test", 2, 60_000)).resolves.toMatchObject({ ok: true, remaining: 1 });
    await expect(rateLimit("test", 2, 60_000)).resolves.toMatchObject({ ok: true, remaining: 0 });
    await expect(rateLimit("test", 2, 60_000)).resolves.toMatchObject({ ok: false, remaining: 0 });
  });

  it("falls back to memory when distributed backend fails", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "token");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    await expect(rateLimit("fallback", 1, 60_000)).resolves.toMatchObject({ ok: true });
    await expect(rateLimit("fallback", 1, 60_000)).resolves.toMatchObject({ ok: false });
  });
});
