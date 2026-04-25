import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

// ─── Hoist mock variables so they are available inside vi.mock factories ──────

const { mockSelect, mockInsert, mockUpdate, mockAuth } = vi.hoisted(() => ({
  mockSelect: vi.fn(),
  mockInsert: vi.fn(),
  mockUpdate: vi.fn(),
  mockAuth: vi.fn(),
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

import { GET, POST, DELETE } from "@/app/api/keys/route";

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
    orderBy: () => Promise.resolve(rows),
  };
  mockSelect.mockReturnValue(chain);
}

function makeInsertChain() {
  const chain = {
    values: () => Promise.resolve(),
  };
  mockInsert.mockReturnValue(chain);
}

function makeUpdateChain() {
  const chain = {
    set: () => chain,
    where: () => Promise.resolve(),
  };
  mockUpdate.mockReturnValue(chain);
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── GET ─────────────────────────────────────────────────────────────────────

describe("GET /api/keys", () => {
  it("returns 401 when not authenticated", async () => {
    unauthedSession();
    const res = await GET();
    expect(res.status).toBe(401);
  });

  it("returns array of keys for authenticated user", async () => {
    authedSession();
    const fakeKeys = [
      { id: "k1", name: "prod", keyPrefix: "bs_live_xyz1", lastUsedAt: null, revokedAt: null, createdAt: new Date() },
    ];
    makeSelectChain(fakeKeys);

    const res = await GET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(1);
    expect(body[0].name).toBe("prod");
  });

  it("returns empty array when user has no keys", async () => {
    authedSession();
    makeSelectChain([]);
    const res = await GET();
    const body = await res.json();
    expect(body).toEqual([]);
  });
});

// ─── POST ────────────────────────────────────────────────────────────────────

describe("POST /api/keys", () => {
  it("returns 401 when not authenticated", async () => {
    unauthedSession();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "POST",
      body: JSON.stringify({ name: "test" }),
    });
    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("creates a key and returns fullKey, prefix, name", async () => {
    authedSession();
    makeInsertChain();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "POST",
      body: JSON.stringify({ name: "ci-key" }),
    });
    const res = await POST(req);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toHaveProperty("fullKey");
    expect(body).toHaveProperty("prefix");
    expect(body.name).toBe("ci-key");
    expect(body.fullKey.startsWith("bs_live_")).toBe(true);
  });

  it("uses 'Unnamed Key' when no name provided", async () => {
    authedSession();
    makeInsertChain();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "POST",
      body: JSON.stringify({}),
    });
    const res = await POST(req);
    const body = await res.json();
    expect(body.name).toBe("Unnamed Key");
  });

  it("truncates name to 64 chars", async () => {
    authedSession();
    makeInsertChain();
    const longName = "a".repeat(100);
    const req = new NextRequest("http://localhost/api/keys", {
      method: "POST",
      body: JSON.stringify({ name: longName }),
    });
    const res = await POST(req);
    const body = await res.json();
    expect(body.name.length).toBeLessThanOrEqual(64);
  });
});

// ─── DELETE ──────────────────────────────────────────────────────────────────

describe("DELETE /api/keys", () => {
  it("returns 401 when not authenticated", async () => {
    unauthedSession();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "DELETE",
      body: JSON.stringify({ id: "k1" }),
    });
    const res = await DELETE(req);
    expect(res.status).toBe(401);
  });

  it("returns 400 when no id provided", async () => {
    authedSession();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "DELETE",
      body: JSON.stringify({}),
    });
    const res = await DELETE(req);
    expect(res.status).toBe(400);
  });

  it("revokes key and returns ok", async () => {
    authedSession();
    makeUpdateChain();
    const req = new NextRequest("http://localhost/api/keys", {
      method: "DELETE",
      body: JSON.stringify({ id: "key-uuid-123" }),
    });
    const res = await DELETE(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });
});
