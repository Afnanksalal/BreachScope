import { NextRequest, NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { organizationMembers, users } from "@/lib/schema";
import { authorizeScim, isScimAuthorized } from "@/lib/scim";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const auth = authorizeScim(req);
  if (!isScimAuthorized(auth)) return auth;

  const rows = await db
    .select({ user: users })
    .from(organizationMembers)
    .innerJoin(users, eq(organizationMembers.userId, users.id))
    .where(eq(organizationMembers.organizationId, auth.organizationId))
    .limit(200);

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: rows.length,
    Resources: rows.map(({ user }) => scimUser(user, true)),
  });
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const auth = authorizeScim(req);
  if (!isScimAuthorized(auth)) return auth;

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const email = typeof body?.["userName"] === "string" ? body["userName"].trim().toLowerCase() : "";
  if (!email) return NextResponse.json({ error: "userName required" }, { status: 400 });

  const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1);
  const user = existing ?? (await db.insert(users).values({ email, name: displayName(body) }).returning())[0];
  if (!user) return NextResponse.json({ error: "Failed to create user" }, { status: 500 });

  await db
    .insert(organizationMembers)
    .values({ organizationId: auth.organizationId, userId: user.id, role: "member" })
    .onConflictDoNothing();

  return NextResponse.json(scimUser(user, true), { status: existing ? 200 : 201 });
}

function scimUser(user: typeof users.$inferSelect, active: boolean): Record<string, unknown> {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: user.id,
    userName: user.email,
    name: { formatted: user.name ?? user.email },
    active,
    emails: [{ value: user.email, primary: true }],
  };
}

function displayName(body: Record<string, unknown> | null): string | null {
  const name = body?.["name"];
  if (typeof name === "object" && name !== null && typeof (name as Record<string, unknown>)["formatted"] === "string") {
    return String((name as Record<string, unknown>)["formatted"]).slice(0, 120);
  }
  return null;
}
