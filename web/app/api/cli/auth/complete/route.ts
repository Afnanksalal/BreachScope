import { NextRequest, NextResponse } from "next/server";
import { and, eq, gt, isNull } from "drizzle-orm";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { generateApiKey } from "@/lib/api-keys";
import { apiKeys, cliAuthStates } from "@/lib/schema";

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

  const [claimed] = await db
    .update(cliAuthStates)
    .set({ userId: session.user.id })
    .where(
      and(
        eq(cliAuthStates.state, state),
        isNull(cliAuthStates.userId),
        isNull(cliAuthStates.token),
        isNull(cliAuthStates.usedAt),
        gt(cliAuthStates.expiresAt, new Date())
      )
    )
    .returning({ id: cliAuthStates.id });

  if (!claimed) {
    return NextResponse.json({ error: "State expired, already used, or invalid" }, { status: 410 });
  }

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
    userId: session.user.id,
    name: "CLI (device flow)",
    scopes: ["scan:write", "config:read", "settings:write"],
    keyHash: hash,
    keyPrefix: prefix,
  });

  await db
    .update(cliAuthStates)
    .set({ token: fullKey })
    .where(and(eq(cliAuthStates.state, state), isNull(cliAuthStates.usedAt)));

  return NextResponse.json({ ok: true });
}
