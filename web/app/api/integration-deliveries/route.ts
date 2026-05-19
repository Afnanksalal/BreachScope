import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { canManageProject } from "@/lib/access-control";
import { integrationDeliveries } from "@/lib/schema";
import { and, desc, eq } from "drizzle-orm";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const projectId = req.nextUrl.searchParams.get("projectId");
  const scanId = req.nextUrl.searchParams.get("scanId");
  if (!projectId) return NextResponse.json([]);
  if (!await canManageProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select({
      id: integrationDeliveries.id,
      provider: integrationDeliveries.provider,
      action: integrationDeliveries.action,
      status: integrationDeliveries.status,
      attempts: integrationDeliveries.attempts,
      maxAttempts: integrationDeliveries.maxAttempts,
      scanId: integrationDeliveries.scanId,
      nextAttemptAt: integrationDeliveries.nextAttemptAt,
      deliveredAt: integrationDeliveries.deliveredAt,
      externalUrl: integrationDeliveries.externalUrl,
      lastError: integrationDeliveries.lastError,
      createdAt: integrationDeliveries.createdAt,
    })
    .from(integrationDeliveries)
    .where(and(
      eq(integrationDeliveries.projectId, projectId),
      scanId ? eq(integrationDeliveries.scanId, scanId) : undefined,
    ))
    .orderBy(desc(integrationDeliveries.createdAt))
    .limit(100);

  return NextResponse.json(rows);
}
