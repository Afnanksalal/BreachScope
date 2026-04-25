import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { cliAuthStates, apiKeys } from "@/lib/schema";
import { generateApiKey } from "@/lib/api-keys";
import { eq, and, isNull, gt } from "drizzle-orm";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body: unknown = await req.json().catch(() => null);
  const state =
    typeof body === "object" && body !== null && "state" in body
      ? String((body as Record<string, unknown>).state ?? "").trim()
      : "";

  if (!state) {
    return NextResponse.json({ error: "Missing state" }, { status: 400 });
  }

  const [record] = await db
    .select({ id: cliAuthStates.id })
    .from(cliAuthStates)
    .where(
      and(
        eq(cliAuthStates.state, state),
        isNull(cliAuthStates.usedAt),
        gt(cliAuthStates.expiresAt, new Date())
      )
    )
    .limit(1);

  if (!record) {
    return NextResponse.json({ error: "State expired or invalid" }, { status: 410 });
  }

  const { fullKey, prefix, hash } = generateApiKey();

  await db.insert(apiKeys).values({
    userId:    session.user.id,
    name:      "CLI (device flow)",
    keyHash:   hash,
    keyPrefix: prefix,
  });

  await db
    .update(cliAuthStates)
    .set({ token: fullKey, userId: session.user.id })
    .where(eq(cliAuthStates.state, state));

  return NextResponse.json({ ok: true });
}
