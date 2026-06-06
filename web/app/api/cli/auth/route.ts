import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { clientIp, rateLimit } from "@/lib/rate-limit";
import { APP_URL } from "@/lib/site";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const limited = await rateLimit(`cli-auth-init:${clientIp(req)}`, 30, 10 * 60 * 1000);
  if (!limited.ok) {
    return NextResponse.json({ error: "Too many authentication attempts" }, { status: 429 });
  }

  const state = randomUUID();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  await db.insert(cliAuthStates).values({ state, expiresAt });

  const authUrl = `${APP_URL}/cli-auth?state=${encodeURIComponent(state)}`;

  return NextResponse.json({ state, authUrl, expiresIn: 300 }, { status: 201 });
}
