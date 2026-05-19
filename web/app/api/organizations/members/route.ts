import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { canManageOrganization, normalizeRole } from "@/lib/access-control";
import { organizationMembers, users } from "@/lib/schema";
import { and, eq } from "drizzle-orm";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const organizationId = req.nextUrl.searchParams.get("organizationId");
  if (!organizationId || !await canManageOrganization(session.user.id, organizationId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select({
      userId: users.id,
      email: users.email,
      name: users.name,
      role: organizationMembers.role,
      createdAt: organizationMembers.createdAt,
    })
    .from(organizationMembers)
    .innerJoin(users, eq(organizationMembers.userId, users.id))
    .where(eq(organizationMembers.organizationId, organizationId));

  return NextResponse.json(rows);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const organizationId = typeof body?.["organizationId"] === "string" ? body["organizationId"] : "";
  const email = typeof body?.["email"] === "string" ? body["email"].trim().toLowerCase() : "";
  const role = normalizeRole(body?.["role"]);
  if (!organizationId || !email) return NextResponse.json({ error: "organizationId and email required" }, { status: 400 });
  if (!await canManageOrganization(session.user.id, organizationId)) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const [user] = await db.select({ id: users.id, email: users.email, name: users.name }).from(users).where(eq(users.email, email)).limit(1);
  if (!user) return NextResponse.json({ error: "User must sign up before they can be added to a workspace" }, { status: 404 });

  await db
    .insert(organizationMembers)
    .values({ organizationId, userId: user.id, role })
    .onConflictDoUpdate({
      target: [organizationMembers.organizationId, organizationMembers.userId],
      set: { role },
    });

  return NextResponse.json({ userId: user.id, email: user.email, name: user.name, role }, { status: 201 });
}

export async function PATCH(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const organizationId = typeof body?.["organizationId"] === "string" ? body["organizationId"] : "";
  const userId = typeof body?.["userId"] === "string" ? body["userId"] : "";
  const role = normalizeRole(body?.["role"]);
  if (!organizationId || !userId) return NextResponse.json({ error: "organizationId and userId required" }, { status: 400 });
  if (!await canManageOrganization(session.user.id, organizationId)) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (userId === session.user.id && role !== "owner") return NextResponse.json({ error: "Owners cannot demote themselves" }, { status: 400 });

  await db
    .update(organizationMembers)
    .set({ role })
    .where(and(eq(organizationMembers.organizationId, organizationId), eq(organizationMembers.userId, userId)));

  return NextResponse.json({ ok: true });
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const organizationId = typeof body?.["organizationId"] === "string" ? body["organizationId"] : "";
  const userId = typeof body?.["userId"] === "string" ? body["userId"] : "";
  if (!organizationId || !userId) return NextResponse.json({ error: "organizationId and userId required" }, { status: 400 });
  if (!await canManageOrganization(session.user.id, organizationId)) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (userId === session.user.id) return NextResponse.json({ error: "Owners cannot remove themselves" }, { status: 400 });

  await db
    .delete(organizationMembers)
    .where(and(eq(organizationMembers.organizationId, organizationId), eq(organizationMembers.userId, userId)));

  return NextResponse.json({ ok: true });
}
