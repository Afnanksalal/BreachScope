import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { policies, projects } from "@/lib/schema";
import { and, eq } from "drizzle-orm";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const projectId = req.nextUrl.searchParams.get("projectId");
  if (!projectId) return NextResponse.json([]);
  if (projectId) {
    const owned = await ownsProject(session.user.id, projectId);
    if (!owned) return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select()
    .from(policies)
    .where(eq(policies.projectId, projectId));

  return NextResponse.json(rows);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const name = typeof body?.["name"] === "string" ? body["name"].trim().slice(0, 120) : "";
  const projectId = typeof body?.["projectId"] === "string" ? body["projectId"] : null;
  const document = typeof body?.["document"] === "object" && body["document"] !== null
    ? body["document"] as Record<string, unknown>
    : null;

  if (!name || !document) {
    return NextResponse.json({ error: "Policy name and document required" }, { status: 400 });
  }
  if (projectId && !await ownsProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const [policy] = await db
    .insert(policies)
    .values({ name, projectId, document, enabled: body?.["enabled"] !== false })
    .returning();

  return NextResponse.json(policy, { status: 201 });
}

async function ownsProject(userId: string, projectId: string): Promise<boolean> {
  const [project] = await db
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.ownerUserId, userId)))
    .limit(1);
  return Boolean(project);
}
