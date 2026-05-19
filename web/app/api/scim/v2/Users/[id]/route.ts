import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { users } from "@/lib/schema";
import { eq } from "drizzle-orm";

interface Params {
  params: Promise<{ id: string }>;
}

function authorize(req: NextRequest): boolean {
  const token = process.env.SCIM_BEARER_TOKEN;
  return Boolean(token && req.headers.get("authorization") === `Bearer ${token}`);
}

export async function PATCH(req: NextRequest, ctx: Params): Promise<NextResponse> {
  if (!authorize(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await ctx.params;
  const body = await req.json().catch(() => null) as Record<string, unknown> | null;

  const active = typeof body?.["active"] === "boolean" ? body["active"] : true;
  if (!active) {
    await db.update(users).set({ passwordHash: null }).where(eq(users.id, id));
    return NextResponse.json({ id, active: false });
  }

  const name = typeof body?.["displayName"] === "string" ? body["displayName"].slice(0, 120) : undefined;
  const [updated] = await db.update(users).set({ name }).where(eq(users.id, id)).returning();
  return NextResponse.json({ id: updated?.id ?? id, userName: updated?.email, active: true });
}

export async function DELETE(req: NextRequest, ctx: Params): Promise<NextResponse> {
  if (!authorize(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await ctx.params;
  await db.update(users).set({ passwordHash: null }).where(eq(users.id, id));
  return new NextResponse(null, { status: 204 });
}
