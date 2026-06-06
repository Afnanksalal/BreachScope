import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const { mockInsert, mockSelect, mockUpdate, mockAuth, mockRateLimit } = vi.hoisted(() => ({
  mockInsert: vi.fn(),
  mockSelect: vi.fn(),
  mockUpdate: vi.fn(),
  mockAuth: vi.fn(),
  mockRateLimit: vi.fn(),
}));

vi.mock("@/lib/db", () => ({
  db: {
    insert: mockInsert,
    select: mockSelect,
    update: mockUpdate,
  },
}));

vi.mock("@/lib/auth", () => ({ auth: mockAuth }));
vi.mock("@/lib/rate-limit", () => ({
  clientIp: () => "127.0.0.1",
  rateLimit: mockRateLimit,
}));
vi.mock("@/lib/api-keys", () => ({
  generateApiKey: () => ({ fullKey: "bs_live_full", prefix: "bs_live_full".slice(0, 12), hash: "hash" }),
}));
vi.mock("@/lib/site", () => ({ APP_URL: "http://localhost:3000" }));

import { POST as initCliAuth } from "@/app/api/cli/auth/route";
import { POST as completeCliAuth } from "@/app/api/cli/auth/complete/route";
import { GET as pollCliAuth } from "@/app/api/cli/auth/poll/route";

beforeEach(() => {
  vi.clearAllMocks();
  mockRateLimit.mockResolvedValue({ ok: true, limit: 1, remaining: 1, resetAt: Date.now() + 1000 });
});

describe("CLI auth device flow", () => {
  it("generates server-owned states instead of accepting caller-supplied states", async () => {
    const inserted: Record<string, unknown>[] = [];
    mockInsert.mockReturnValue({ values: (value: Record<string, unknown>) => { inserted.push(value); return Promise.resolve(); } });

    const req = new NextRequest("http://localhost/api/cli/auth", {
      method: "POST",
      body: JSON.stringify({ state: "00000000-0000-4000-8000-000000000000" }),
    });
    const res = await initCliAuth(req);
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.state).not.toBe("00000000-0000-4000-8000-000000000000");
    expect(inserted[0]?.state).toBe(body.state);
    expect(body.authUrl).toContain(`/cli-auth?state=${encodeURIComponent(body.state)}`);
  });

  it("completes authorization without marking the state consumed", async () => {
    mockAuth.mockResolvedValue({ user: { id: "user-1" } });
    const updateSetCalls: unknown[] = [];
    const updateQueue = [
      updateReturning([{ id: "state-1" }], updateSetCalls),
      updatePromise(updateSetCalls),
      updatePromise(updateSetCalls),
    ];
    mockUpdate.mockImplementation(() => updateQueue.shift());
    mockInsert.mockReturnValue({ values: () => Promise.resolve() });

    const req = new NextRequest("http://localhost/api/cli/auth/complete", {
      method: "POST",
      body: JSON.stringify({ state: "00000000-0000-4000-8000-000000000001" }),
    });
    const res = await completeCliAuth(req);

    expect(res.status).toBe(200);
    expect(updateSetCalls[0]).toEqual({ userId: "user-1" });
    expect(updateSetCalls[2]).toEqual({ token: "bs_live_full" });
  });

  it("poll consumes and clears the token after returning it once", async () => {
    mockSelect.mockReturnValue({
      from: () => ({
        where: () => ({
          limit: () => Promise.resolve([{ token: "bs_live_full", expiresAt: new Date(Date.now() + 1000), usedAt: null }]),
        }),
      }),
    });

    const updateSetCalls: unknown[] = [];
    const updateQueue = [
      updateReturning([{ token: "bs_live_full" }], updateSetCalls),
      updatePromise(updateSetCalls),
    ];
    mockUpdate.mockImplementation(() => updateQueue.shift());

    const req = new NextRequest("http://localhost/api/cli/auth/poll?state=00000000-0000-4000-8000-000000000001");
    const res = await pollCliAuth(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ status: "complete", token: "bs_live_full" });
    expect(updateSetCalls[0]).toEqual({ usedAt: expect.any(Date) });
    expect(updateSetCalls[1]).toEqual({ token: null });
  });
});

function updateReturning(rows: unknown[], setCalls: unknown[]) {
  const chain = {
    set: (value: unknown) => { setCalls.push(value); return chain; },
    where: () => chain,
    returning: () => Promise.resolve(rows),
  };
  return chain;
}

function updatePromise(setCalls: unknown[]) {
  const chain = {
    set: (value: unknown) => { setCalls.push(value); return chain; },
    where: () => Promise.resolve(),
  };
  return chain;
}
