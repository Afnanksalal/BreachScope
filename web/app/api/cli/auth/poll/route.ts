import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { eq, and, isNull } from "drizzle-orm";
import { clientIp, rateLimit } from "@/lib/rate-limit";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type PollStatus = "authorization_pending" | "complete" | "expired";

interface PollResponse {
  status: PollStatus;
  token?: string;
}

export async function GET(req: NextRequest): Promise<NextResponse<PollResponse | { error: string }>> {
  const state = req.nextUrl.searchParams.get("state")?.trim() ?? "";
  const limited = await rateLimit(`cli-auth-poll:${clientIp(req)}:${state || "missing"}`, 120, 10 * 60 * 1000);
  if (!limited.ok) {
    return NextResponse.json({ error: "Too many polling requests" }, { status: 429 });
  }

  if (!state || !UUID_RE.test(state)) {
    return NextResponse.json({ error: "Missing or invalid state" }, { status: 400 });
  }

  const [record] = await db
    .select({
      token:     cliAuthStates.token,
      expiresAt: cliAuthStates.expiresAt,
      usedAt:    cliAuthStates.usedAt,
    })
    .from(cliAuthStates)
    .where(eq(cliAuthStates.state, state))
    .limit(1);

  if (!record) {
    return NextResponse.json({ error: "Invalid state" }, { status: 404 });
  }

  if (record.expiresAt < new Date()) {
    return NextResponse.json({ status: "expired" }, { status: 410 });
  }

  if (record.usedAt) {
    return NextResponse.json({ status: "expired" }, { status: 410 });
  }

  if (!record.token) {
    return NextResponse.json({ status: "authorization_pending" }, { status: 202 });
  }

  // Atomically mark the device flow as used so parallel poll requests cannot replay the token.
  const [consumed] = await db
    .update(cliAuthStates)
    .set({ usedAt: new Date() })
    .where(and(eq(cliAuthStates.state, state), isNull(cliAuthStates.usedAt)))
    .returning({ token: cliAuthStates.token });

  if (!consumed?.token) {
    return NextResponse.json({ status: "expired" }, { status: 410 });
  }

  return NextResponse.json({ status: "complete", token: consumed.token });
}
