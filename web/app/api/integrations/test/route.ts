import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { integrations, projects } from "@/lib/schema";
import { dispatchSecurityNotification } from "@/lib/integration-executors";
import { decrypt } from "@/lib/crypto";
import { testGitHubAccess } from "@/lib/github-audit";
import { canManageProject } from "@/lib/access-control";
import { eq } from "drizzle-orm";

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
    .where(eq(integrations.id, integrationId))
    .limit(1);

  if (!row || !await canManageProject(session.user.id, row.project.id)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const secret = decryptOptional(row.integration.secretRef);
  if (row.integration.provider === "github") {
    const repoFullName = stringConfig(row.integration.config, "repoFullName") || row.project.repositoryUrl || "";
    if (!secret) return NextResponse.json({ provider: "github", ok: false, status: 400, error: "Missing GitHub token" }, { status: 400 });
    const result = await testGitHubAccess(secret, repoFullName);
    return NextResponse.json({
      provider: "github",
      ok: result.ok,
      status: result.status,
      message: result.message,
      url: result.htmlUrl,
    }, { status: result.ok ? 200 : 400 });
  }

  const result = await dispatchSecurityNotification({
    provider: row.integration.provider,
    name: row.integration.name,
    config: row.integration.config,
    secret,
  }, {
    project: row.project.name,
    title: "BreachScope integration test",
    severity: "info",
    summary: "This is a test notification from BreachScope.",
  });

  return NextResponse.json(result, { status: result.ok ? 200 : 400 });
}

function decryptOptional(value: string | null): string | null {
  if (!value) return null;
  try { return decrypt(value); } catch { return null; }
}

function stringConfig(config: Record<string, unknown> | null, key: string): string {
  const value = config?.[key];
  return typeof value === "string" ? value : "";
}
