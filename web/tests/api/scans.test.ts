import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const { mockSelect, mockInsert, mockUpdate, mockAuth, mockValidateApiKey, mockResolveScanProject, mockDispatchScanIntegrations } = vi.hoisted(() => ({
  mockSelect: vi.fn(),
  mockInsert: vi.fn(),
  mockUpdate: vi.fn(),
  mockAuth: vi.fn(),
  mockValidateApiKey: vi.fn(),
  mockResolveScanProject: vi.fn(),
  mockDispatchScanIntegrations: vi.fn(),
}));

vi.mock("@/lib/db", () => ({
  db: {
    select: mockSelect,
    insert: mockInsert,
    update: mockUpdate,
  },
}));

vi.mock("@/lib/auth", () => ({
  auth: mockAuth,
}));

vi.mock("@/lib/middleware-utils", () => ({
  validateApiKey: mockValidateApiKey,
  unauthorized: () => new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 }),
  forbidden: () => new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 }),
  hasScope: (authed: { scopes?: string[] }, scope: string) => (
    Array.isArray(authed.scopes) ? authed.scopes.includes(scope) : ["scan:write", "config:read"].includes(scope)
  ),
  ok: (data: unknown) => new Response(JSON.stringify(data)),
}));

vi.mock("@/lib/integration-pipeline", () => ({
  resolveScanProject: mockResolveScanProject,
  dispatchScanIntegrations: mockDispatchScanIntegrations,
}));

import { GET, POST } from "@/app/api/scans/route";

const SCAN_ID = "scan-uuid-001";
const USER_ID = "user-abc";
const API_KEY_ID = "key-uuid-001";

function makeSelectChain(rows: unknown[]) {
  const chain = {
    from: () => chain,
    where: () => chain,
    orderBy: () => chain,
    limit: () => Promise.resolve(rows),
  };
  mockSelect.mockReturnValue(chain);
}

function makeInsertReturning(returned: unknown[]) {
  // The scan insert calls .values(...).returning(...) → needs a chainable thenable
  // The findings insert calls await .values(...) with no .returning()
  // Use a single mock that handles both patterns: values() returns a promise-like
  // that also has .returning() for when it's needed.
  let callCount = 0;
  mockInsert.mockImplementation(() => ({
    values: () => {
      callCount++;
      if (callCount === 1) {
        // First insert: scan — caller does .returning()
        return {
          returning: () => Promise.resolve(returned),
        };
      }
      // Second insert: findings — caller just awaits .values()
      return Promise.resolve(undefined);
    },
  }));
}

beforeEach(() => {
  vi.clearAllMocks();
  mockResolveScanProject.mockResolvedValue(null);
  mockDispatchScanIntegrations.mockResolvedValue([]);
});

// ─── GET ─────────────────────────────────────────────────────────────────────

describe("GET /api/scans", () => {
  it("returns 401 when not authenticated", async () => {
    mockAuth.mockResolvedValue(null);
    const req = new NextRequest("http://localhost/api/scans");
    const res = await GET(req);
    expect(res.status).toBe(401);
  });

  it("returns scans array for authenticated user", async () => {
    mockAuth.mockResolvedValue({ user: { id: USER_ID } });
    const fakeScans = [{ id: SCAN_ID, mode: "basic", scanMode: "all", findingsTotal: 3 }];
    makeSelectChain(fakeScans);
    const req = new NextRequest("http://localhost/api/scans");
    const res = await GET(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body[0].id).toBe(SCAN_ID);
  });
});

// ─── POST ─────────────────────────────────────────────────────────────────────

describe("POST /api/scans", () => {
  it("returns 401 when API key is invalid", async () => {
    mockValidateApiKey.mockResolvedValue(null);
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ mode: "basic", scanMode: "all", startedAt: new Date().toISOString() }),
    });
    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("returns 400 when required fields are missing", async () => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID });
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ mode: "basic" }), // missing scanMode + startedAt
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("returns 403 when API key lacks scan:write scope", async () => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID, scopes: ["config:read"] });
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ mode: "basic", scanMode: "all", startedAt: new Date().toISOString() }),
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
  });

  it("returns 400 for invalid JSON body", async () => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID });
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: "not-json",
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("creates scan and returns id + ok on success", async () => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID });
    makeInsertReturning([{ id: SCAN_ID }]);

    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({
        mode: "basic",
        scanMode: "all",
        startedAt: new Date().toISOString(),
        project: "my-app",
        toolsScanned: 15,
      }),
    });
    const res = await POST(req);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.id).toBe(SCAN_ID);
    expect(body.ok).toBe(true);
    expect(body.deliveries).toEqual([]);
    expect(mockDispatchScanIntegrations).toHaveBeenCalledOnce();
  });

  it("inserts findings when provided", async () => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID });
    makeInsertReturning([{ id: SCAN_ID }]);

    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({
        mode: "deep",
        scanMode: "breach",
        startedAt: new Date().toISOString(),
        findings: [
          { title: "A", severity: "critical", category: "code", description: "d" },
          { title: "B", severity: "high",     category: "dependency", description: "d" },
        ],
      }),
    });
    const res = await POST(req);
    expect(res.status).toBe(201);
    // Second insert call is for findings
    expect(mockInsert).toHaveBeenCalledTimes(2);
  });
});

// ─── Body type-guard (tested via POST rejections) ─────────────────────────────

describe("ScanPostBody type guard", () => {
  beforeEach(() => {
    mockValidateApiKey.mockResolvedValue({ userId: USER_ID, apiKeyId: API_KEY_ID });
  });

  it("rejects body missing mode", async () => {
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ scanMode: "all", startedAt: new Date().toISOString() }),
    });
    expect((await POST(req)).status).toBe(400);
  });

  it("rejects body missing scanMode", async () => {
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ mode: "basic", startedAt: new Date().toISOString() }),
    });
    expect((await POST(req)).status).toBe(400);
  });

  it("rejects body missing startedAt", async () => {
    const req = new NextRequest("http://localhost/api/scans", {
      method: "POST",
      body: JSON.stringify({ mode: "basic", scanMode: "all" }),
    });
    expect((await POST(req)).status).toBe(400);
  });
});
