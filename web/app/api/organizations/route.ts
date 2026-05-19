import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { getUserOrganizations, slugify } from "@/lib/access-control";
import { organizationMembers, organizations } from "@/lib/schema";

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return NextResponse.json(await getUserOrganizations(session.user.id));
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const name = typeof body?.["name"] === "string" ? body["name"].trim().slice(0, 120) : "";
  const ssoDomain = typeof body?.["ssoDomain"] === "string" ? body["ssoDomain"].trim().toLowerCase().slice(0, 180) : "";
  if (!name) return NextResponse.json({ error: "Workspace name required" }, { status: 400 });

  const [organization] = await db
    .insert(organizations)
    .values({ name, slug: slugify(name), ssoDomain: ssoDomain || null })
    .returning();
  if (!organization) return NextResponse.json({ error: "Workspace could not be created" }, { status: 500 });

  await db.insert(organizationMembers).values({
    organizationId: organization.id,
    userId: session.user.id,
    role: "owner",
  });

  return NextResponse.json({ ...organization, role: "owner", projectCount: 0 }, { status: 201 });
}
