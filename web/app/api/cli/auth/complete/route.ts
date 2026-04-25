import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { cliAuthStates, apiKeys } from "@/lib/schema";
import { generateApiKey } from "@/lib/api-keys";
import { eq, and, isNull, gt, isNotNull } from "drizzle-orm";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

  if (!state || !UUID_RE.test(state)) {
    return NextResponse.json({ error: "Missing or invalid state" }, { status: 400 });
  }

  // Atomically mark the state as used — prevents duplicate key generation
  // if the page loads twice (Strict Mode, retry, etc.)
  const updated = await db
    .update(cliAuthStates)
    .set({ userId: session.user.id, usedAt: new Date() })
    .where(
      and(
        eq(cliAuthStates.state, state),
        isNull(cliAuthStates.usedAt),
        gt(cliAuthStates.expiresAt, new Date())
      )
    )
    .returning({ id: cliAuthStates.id });

  if (updated.length === 0) {
    return NextResponse.json({ error: "State expired, already used, or invalid" }, { status: 410 });
  }

  // Revoke any existing CLI device-flow keys for this user so we never accumulate them
  await db
    .update(apiKeys)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(apiKeys.userId, session.user.id),
        eq(apiKeys.name, "CLI (device flow)"),
        isNull(apiKeys.revokedAt)
      )
    );

  const { fullKey, prefix, hash } = generateApiKey();

  await db.insert(apiKeys).values({
    userId:    session.user.id,
    name:      "CLI (device flow)",
    keyHash:   hash,
    keyPrefix: prefix,
  });

  // Store the token so the polling endpoint can return it once
  await db
    .update(cliAuthStates)
    .set({ token: fullKey })
    .where(eq(cliAuthStates.state, state));

  return NextResponse.json({ ok: true });
}
