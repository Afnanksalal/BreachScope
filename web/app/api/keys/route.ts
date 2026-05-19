import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { apiKeys } from "@/lib/schema";
import { generateApiKey } from "@/lib/api-keys";
import { canManageProject, getProjectForUser } from "@/lib/access-control";
import { DEFAULT_API_KEY_SCOPES } from "@/lib/middleware-utils";
import { eq, and, isNull } from "drizzle-orm";

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const rows = await db
    .select({
      id:         apiKeys.id,
      name:       apiKeys.name,
      keyPrefix:  apiKeys.keyPrefix,
      scopes:     apiKeys.scopes,
      organizationId: apiKeys.organizationId,
      projectId:  apiKeys.projectId,
      lastUsedAt: apiKeys.lastUsedAt,
      revokedAt:  apiKeys.revokedAt,
      createdAt:  apiKeys.createdAt,
    })
    .from(apiKeys)
    .where(and(eq(apiKeys.userId, session.user.id), isNull(apiKeys.revokedAt)))
    .orderBy(apiKeys.createdAt);

  return NextResponse.json(rows);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body: unknown = await req.json().catch(() => ({}));
  const name =
    typeof body === "object" && body !== null && "name" in body
      ? String((body as Record<string, unknown>).name ?? "").slice(0, 64) || "Unnamed Key"
      : "Unnamed Key";
  const requestedScopes = typeof body === "object" && body !== null && Array.isArray((body as Record<string, unknown>).scopes)
    ? (body as { scopes: unknown[] }).scopes
    : [];
  const scopes = normalizeScopes(requestedScopes);
  const projectId = typeof body === "object" && body !== null && typeof (body as Record<string, unknown>).projectId === "string"
    ? ((body as Record<string, string>).projectId || "").trim()
    : "";
  const project = projectId ? await getProjectForUser(session.user.id, projectId) : null;
  if (projectId && (!project || !await canManageProject(session.user.id, projectId))) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  const { fullKey, prefix, hash } = generateApiKey();

  await db.insert(apiKeys).values({
    userId:         session.user.id,
    organizationId: project?.organizationId ?? null,
    projectId:      project?.id ?? null,
    name,
    scopes,
    keyHash:   hash,
    keyPrefix: prefix,
  });

  // fullKey returned ONCE — never stored in the DB
  return NextResponse.json({ fullKey, prefix, name, scopes }, { status: 201 });
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body: unknown = await req.json().catch(() => ({}));
  const id =
    typeof body === "object" && body !== null && "id" in body
      ? String((body as Record<string, unknown>).id ?? "")
      : "";

  if (!id) {
    return NextResponse.json({ error: "Missing key id" }, { status: 400 });
  }

  await db
    .update(apiKeys)
    .set({ revokedAt: new Date() })
    .where(and(eq(apiKeys.id, id), eq(apiKeys.userId, session.user.id)));

  return NextResponse.json({ ok: true });
}

function normalizeScopes(scopes: unknown[]): string[] {
  const allowed = new Set(["scan:write", "config:read", "secrets:read", "settings:write"]);
  const normalized = scopes.filter((scope): scope is string => typeof scope === "string" && allowed.has(scope));
  return normalized.length > 0 ? [...new Set(normalized)] : [...DEFAULT_API_KEY_SCOPES];
}
