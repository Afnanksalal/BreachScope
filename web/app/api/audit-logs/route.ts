import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { canManageProject } from "@/lib/access-control";
import { auditLogs } from "@/lib/schema";
import { and, desc, eq, ilike } from "drizzle-orm";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const projectId = req.nextUrl.searchParams.get("projectId");
  if (!projectId) return NextResponse.json([]);

  if (!await canManageProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const action = req.nextUrl.searchParams.get("action");
  const targetType = req.nextUrl.searchParams.get("targetType");

  const rows = await db
    .select()
    .from(auditLogs)
    .where(and(
      eq(auditLogs.projectId, projectId),
      action ? ilike(auditLogs.action, `%${action}%`) : undefined,
      targetType ? eq(auditLogs.targetType, targetType) : undefined,
    ))
    .orderBy(desc(auditLogs.createdAt))
    .limit(200);

  return NextResponse.json(rows);
}
