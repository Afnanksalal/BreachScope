import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { auditLogs, findings, scans } from "@/lib/schema";
import { and, eq } from "drizzle-orm";

const STATUSES = new Set(["open", "triaged", "accepted-risk", "false-positive", "fixed"]);
const VEX_STATUSES = new Set(["affected", "not_affected", "fixed", "under_investigation"]);

interface Params {
  params: Promise<{ id: string }>;
}

export async function PATCH(req: NextRequest, ctx: Params): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await ctx.params;
  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return NextResponse.json({ error: "Invalid body" }, { status: 400 });

  const [owned] = await db
    .select({ scanId: findings.scanId, projectId: scans.projectId })
    .from(findings)
    .innerJoin(scans, eq(findings.scanId, scans.id))
    .where(and(eq(findings.id, id), eq(scans.userId, session.user.id)))
    .limit(1);

  if (!owned) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const status = typeof body["status"] === "string" && STATUSES.has(body["status"]) ? body["status"] : undefined;
  const vexStatus = typeof body["vexStatus"] === "string" && VEX_STATUSES.has(body["vexStatus"]) ? body["vexStatus"] : undefined;
  const acceptedRiskReason = typeof body["acceptedRiskReason"] === "string" ? body["acceptedRiskReason"].slice(0, 2000) : undefined;
  const suppressedUntil = typeof body["suppressedUntil"] === "string" && !Number.isNaN(Date.parse(body["suppressedUntil"]))
    ? new Date(body["suppressedUntil"])
    : undefined;
  const dueAt = typeof body["dueAt"] === "string" && !Number.isNaN(Date.parse(body["dueAt"]))
    ? new Date(body["dueAt"])
    : undefined;

  const [updated] = await db
    .update(findings)
    .set({
      status,
      vexStatus,
      acceptedRiskReason,
      suppressedUntil,
      dueAt,
      assigneeId: typeof body["assigneeId"] === "string" ? body["assigneeId"] : undefined,
    })
    .where(eq(findings.id, id))
    .returning();

  await db.insert(auditLogs).values({
    projectId: owned.projectId,
    actorUserId: session.user.id,
    action: "finding.triage.updated",
    targetType: "finding",
    targetId: id,
    metadata: { status, vexStatus, suppressedUntil: suppressedUntil?.toISOString() },
  });

  return NextResponse.json(updated);
}
