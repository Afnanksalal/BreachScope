import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { integrations, projects } from "@/lib/schema";
import { and, eq } from "drizzle-orm";

const PROVIDERS = new Set(["github", "gitlab", "bitbucket", "jira", "linear", "slack", "teams", "pagerduty", "saml", "scim"]);

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const projectId = req.nextUrl.searchParams.get("projectId");
  if (!projectId) return NextResponse.json([]);
  if (!await ownsProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select()
    .from(integrations)
    .where(eq(integrations.projectId, projectId));

  return NextResponse.json(rows);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const projectId = typeof body?.["projectId"] === "string" ? body["projectId"] : null;
  const provider = typeof body?.["provider"] === "string" ? body["provider"].toLowerCase() : "";
  const name = typeof body?.["name"] === "string" ? body["name"].trim().slice(0, 120) : provider;
  const config = typeof body?.["config"] === "object" && body["config"] !== null
    ? body["config"] as Record<string, unknown>
    : {};

  if (!projectId || !PROVIDERS.has(provider)) {
    return NextResponse.json({ error: "Valid projectId and provider required" }, { status: 400 });
  }
  if (!await ownsProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const [integration] = await db
    .insert(integrations)
    .values({ projectId, provider, name, config, enabled: body?.["enabled"] !== false })
    .returning();

  return NextResponse.json(integration, { status: 201 });
}

async function ownsProject(userId: string, projectId: string): Promise<boolean> {
  const [project] = await db
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.ownerUserId, userId)))
    .limit(1);
  return Boolean(project);
}
