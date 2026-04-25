import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { eq, and } from "drizzle-orm";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type PollStatus = "authorization_pending" | "complete" | "expired";

interface PollResponse {
  status: PollStatus;
  token?: string;
}

export async function GET(req: NextRequest): Promise<NextResponse<PollResponse | { error: string }>> {
  const state = req.nextUrl.searchParams.get("state")?.trim() ?? "";

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

  if (!record.token) {
    return NextResponse.json({ status: "authorization_pending" }, { status: 202 });
  }

  // Token is ready — delete the state row so the token can never be replayed
  void db
    .delete(cliAuthStates)
    .where(eq(cliAuthStates.state, state));

  return NextResponse.json({ status: "complete", token: record.token });
}
