import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans, findings } from "@/lib/schema";
import { eq, and } from "drizzle-orm";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  // Verify the scan belongs to this user
  const [scan] = await db
    .select({ id: scans.id })
    .from(scans)
    .where(and(eq(scans.id, id), eq(scans.userId, session.user.id)))
    .limit(1);

  if (!scan) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select()
    .from(findings)
    .where(eq(findings.scanId, id));

  return NextResponse.json(rows);
}
