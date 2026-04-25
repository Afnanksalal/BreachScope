import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const { mockSelect, mockInsert, mockAuth } = vi.hoisted(() => ({
  mockSelect: vi.fn(),
  mockInsert: vi.fn(),
  mockAuth: vi.fn(),
}));

vi.mock("@/lib/db", () => ({
  db: {
    select: mockSelect,
    insert: mockInsert,
  },
}));

vi.mock("@/lib/auth", () => ({
  auth: mockAuth,
}));

import { GET, PUT } from "@/app/api/settings/route";

function authedSession(userId = "user-abc") {
  mockAuth.mockResolvedValue({ user: { id: userId } });
}

function unauthedSession() {
  mockAuth.mockResolvedValue(null);
}

function makeSelectChain(rows: unknown[]) {
  const chain = {
    from: () => chain,
    where: () => chain,
    limit: () => Promise.resolve(rows),
  };
  mockSelect.mockReturnValue(chain);
}

function makeInsertChain() {
  const chain = {
    values: () => chain,
    onConflictDoUpdate: () => Promise.resolve(),
  };
  mockInsert.mockReturnValue(chain);
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── GET ─────────────────────────────────────────────────────────────────────

describe("GET /api/settings", () => {
  it("returns 401 when not authenticated", async () => {
    unauthedSession();
    const res = await GET();
    expect(res.status).toBe(401);
  });

  it("returns defaults when no settings row exists", async () => {
    authedSession();
    makeSelectChain([]);
    const res = await GET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.hasOpenAI).toBe(false);
    expect(body.hasFirecrawl).toBe(false);
    expect(body.defaultMode).toBe("basic");
    expect(body.defaultScanMode).toBe("all");
  });

  it("reports hasOpenAI: true when key is stored", async () => {
    authedSession();
    makeSelectChain([{
      openaiKeyEnc: "iv:tag:data",
      firecrawlKeyEnc: null,
      defaultMode: "deep",
      defaultScanMode: "breach",
    }]);
    const res = await GET();
    const body = await res.json();
    expect(body.hasOpenAI).toBe(true);
    expect(body.hasFirecrawl).toBe(false);
    expect(body.defaultMode).toBe("deep");
    expect(body.defaultScanMode).toBe("breach");
  });

  it("reports hasFirecrawl: true when key is stored", async () => {
    authedSession();
    makeSelectChain([{
      openaiKeyEnc: null,
      firecrawlKeyEnc: "iv:tag:data",
      defaultMode: "basic",
      defaultScanMode: "all",
    }]);
    const res = await GET();
    const body = await res.json();
    expect(body.hasOpenAI).toBe(false);
    expect(body.hasFirecrawl).toBe(true);
  });
});

// ─── PUT ─────────────────────────────────────────────────────────────────────

describe("PUT /api/settings", () => {
  it("returns 401 when not authenticated", async () => {
    unauthedSession();
    const req = new NextRequest("http://localhost/api/settings", {
      method: "PUT",
      body: JSON.stringify({ defaultMode: "deep" }),
    });
    const res = await PUT(req);
    expect(res.status).toBe(401);
  });

  it("returns 400 for invalid JSON body", async () => {
    authedSession();
    const req = new NextRequest("http://localhost/api/settings", {
      method: "PUT",
      body: "not-json",
    });
    const res = await PUT(req);
    expect(res.status).toBe(400);
  });

  it("accepts valid defaultMode values", async () => {
    authedSession();
    for (const mode of ["basic", "major", "deep"]) {
      makeInsertChain();
      const req = new NextRequest("http://localhost/api/settings", {
        method: "PUT",
        body: JSON.stringify({ defaultMode: mode }),
      });
      const res = await PUT(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
    }
  });

  it("ignores invalid defaultMode silently and still returns 200", async () => {
    authedSession();
    makeInsertChain();
    const req = new NextRequest("http://localhost/api/settings", {
      method: "PUT",
      body: JSON.stringify({ defaultMode: "ultra-mode" }),
    });
    const res = await PUT(req);
    expect(res.status).toBe(200);
  });

  it("accepts valid defaultScanMode values", async () => {
    authedSession();
    for (const scanMode of ["all", "breach", "bug"]) {
      makeInsertChain();
      const req = new NextRequest("http://localhost/api/settings", {
        method: "PUT",
        body: JSON.stringify({ defaultScanMode: scanMode }),
      });
      const res = await PUT(req);
      expect(res.status).toBe(200);
    }
  });
});
