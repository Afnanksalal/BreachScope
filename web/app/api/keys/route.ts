import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { apiKeys } from "@/lib/schema";
import { generateApiKey } from "@/lib/api-keys";
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

  const { fullKey, prefix, hash } = generateApiKey();

  await db.insert(apiKeys).values({
    userId:    session.user.id,
    name,
    keyHash:   hash,
    keyPrefix: prefix,
  });

  // fullKey returned ONCE — never stored in the DB
  return NextResponse.json({ fullKey, prefix, name }, { status: 201 });
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
