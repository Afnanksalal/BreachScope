import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { canManageOrganization, getUserOrganizations, slugify } from "@/lib/access-control";
import { projects } from "@/lib/schema";
import { and, eq, inArray, or } from "drizzle-orm";

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const orgs = await getUserOrganizations(session.user.id);
  const orgIds = orgs.map((org) => org.id);
  const rows = await db
    .select()
    .from(projects)
    .where(orgIds.length > 0 ? or(eq(projects.ownerUserId, session.user.id), inArray(projects.organizationId, orgIds)) : eq(projects.ownerUserId, session.user.id));

  return NextResponse.json(rows);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const name = typeof body?.["name"] === "string" ? body["name"].trim().slice(0, 120) : "";
  if (!name) {
    return NextResponse.json({ error: "Project name required" }, { status: 400 });
  }

  const slug = typeof body?.["slug"] === "string" && body["slug"].trim()
    ? slugify(body["slug"])
    : slugify(name);

  const repositoryUrl = typeof body?.["repositoryUrl"] === "string" ? body["repositoryUrl"].slice(0, 500) : null;
  const defaultBranch = typeof body?.["defaultBranch"] === "string" ? body["defaultBranch"].slice(0, 120) : "main";
  const organizationId = typeof body?.["organizationId"] === "string" && body["organizationId"].trim() ? body["organizationId"].trim() : null;
  if (organizationId && !await canManageOrganization(session.user.id, organizationId)) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  const [existing] = await db
    .select({ id: projects.id })
    .from(projects)
    .where(organizationId ? and(eq(projects.organizationId, organizationId), eq(projects.slug, slug)) : and(eq(projects.ownerUserId, session.user.id), eq(projects.slug, slug)))
    .limit(1);

  if (existing) {
    return NextResponse.json({ error: "Project slug already exists" }, { status: 409 });
  }

  const [project] = await db
    .insert(projects)
    .values({ ownerUserId: session.user.id, organizationId, name, slug, repositoryUrl, defaultBranch })
    .returning();

  return NextResponse.json(project, { status: 201 });
}
