import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { integrations, projects } from "@/lib/schema";
import { dispatchSecurityNotification } from "@/lib/integration-executors";
import { and, eq } from "drizzle-orm";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const integrationId = typeof body?.["integrationId"] === "string" ? body["integrationId"] : "";
  if (!integrationId) return NextResponse.json({ error: "integrationId required" }, { status: 400 });

  const [row] = await db
    .select({
      integration: integrations,
      project: projects,
    })
    .from(integrations)
    .innerJoin(projects, eq(integrations.projectId, projects.id))
    .where(and(eq(integrations.id, integrationId), eq(projects.ownerUserId, session.user.id)))
    .limit(1);

  if (!row) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const result = await dispatchSecurityNotification({
    provider: row.integration.provider,
    name: row.integration.name,
    config: row.integration.config,
  }, {
    project: row.project.name,
    title: "BreachScope integration test",
    severity: "info",
    summary: "This is a test notification from BreachScope.",
  });

  return NextResponse.json(result, { status: result.ok ? 200 : 400 });
}
