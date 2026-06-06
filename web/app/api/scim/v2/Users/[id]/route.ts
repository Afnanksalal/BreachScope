import { NextRequest, NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { organizationMembers, users } from "@/lib/schema";
import { authorizeScim, isScimAuthorized } from "@/lib/scim";

interface Params {
  params: Promise<{ id: string }>;
}

export async function PATCH(req: NextRequest, ctx: Params): Promise<NextResponse> {
  const auth = authorizeScim(req);
  if (!isScimAuthorized(auth)) return auth;

  const { id } = await ctx.params;
  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const active = typeof body?.["active"] === "boolean" ? body["active"] : true;

  if (!await hasMembership(auth.organizationId, id)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  if (!active) {
    await db
      .delete(organizationMembers)
      .where(and(eq(organizationMembers.organizationId, auth.organizationId), eq(organizationMembers.userId, id)));
    return NextResponse.json({ id, active: false });
  }

  const name = typeof body?.["displayName"] === "string" ? body["displayName"].slice(0, 120) : undefined;
  const [updated] = await db.update(users).set({ name }).where(eq(users.id, id)).returning();
  return NextResponse.json({ id: updated?.id ?? id, userName: updated?.email, active: true });
}

export async function DELETE(req: NextRequest, ctx: Params): Promise<NextResponse> {
  const auth = authorizeScim(req);
  if (!isScimAuthorized(auth)) return auth;

  const { id } = await ctx.params;
  await db
    .delete(organizationMembers)
    .where(and(eq(organizationMembers.organizationId, auth.organizationId), eq(organizationMembers.userId, id)));
  return new NextResponse(null, { status: 204 });
}

async function hasMembership(organizationId: string, userId: string): Promise<boolean> {
  const [membership] = await db
    .select({ userId: organizationMembers.userId })
    .from(organizationMembers)
    .where(and(eq(organizationMembers.organizationId, organizationId), eq(organizationMembers.userId, userId)))
    .limit(1);
  return Boolean(membership);
}
