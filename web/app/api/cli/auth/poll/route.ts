import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { eq } from "drizzle-orm";

type PollStatus = "authorization_pending" | "complete" | "expired";

interface PollResponse {
  status: PollStatus;
  token?: string;
}

export async function GET(req: NextRequest): Promise<NextResponse<PollResponse | { error: string }>> {
  const state = req.nextUrl.searchParams.get("state");
  if (!state) {
    return NextResponse.json({ error: "Missing state" }, { status: 400 });
  }

  const [record] = await db
    .select({
      token:     cliAuthStates.token,
      expiresAt: cliAuthStates.expiresAt,
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

  // Mark as used — fire and forget
  void db
    .update(cliAuthStates)
    .set({ usedAt: new Date() })
    .where(eq(cliAuthStates.state, state));

  return NextResponse.json({ status: "complete", token: record.token });
}
