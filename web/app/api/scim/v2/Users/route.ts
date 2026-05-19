import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { users } from "@/lib/schema";
import { eq } from "drizzle-orm";

function authorize(req: NextRequest): boolean {
  const token = process.env.SCIM_BEARER_TOKEN;
  return Boolean(token && req.headers.get("authorization") === `Bearer ${token}`);
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  if (!authorize(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const rows = await db.select().from(users).limit(200);
  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: rows.length,
    Resources: rows.map((user) => ({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      id: user.id,
      userName: user.email,
      name: { formatted: user.name ?? user.email },
      active: true,
      emails: [{ value: user.email, primary: true }],
    })),
  });
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!authorize(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const email = typeof body?.["userName"] === "string" ? body["userName"].trim().toLowerCase() : "";
  if (!email) return NextResponse.json({ error: "userName required" }, { status: 400 });

  const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1);
  if (existing) {
    return NextResponse.json({ id: existing.id, userName: existing.email }, { status: 200 });
  }

  const [created] = await db
    .insert(users)
    .values({ email, name: displayName(body) })
    .returning();

  return NextResponse.json({ id: created?.id, userName: created?.email }, { status: 201 });
}

function displayName(body: Record<string, unknown> | null): string | null {
  const name = body?.["name"];
  if (typeof name === "object" && name !== null && typeof (name as Record<string, unknown>)["formatted"] === "string") {
    return String((name as Record<string, unknown>)["formatted"]).slice(0, 120);
  }
  return null;
}
