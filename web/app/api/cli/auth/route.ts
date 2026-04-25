import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { randomUUID } from "crypto";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function POST(req: NextRequest): Promise<NextResponse> {
  let state: string;

  try {
    const body = await req.json() as Record<string, unknown>;
    const candidate = typeof body.state === "string" ? body.state.trim() : "";
    // Accept only valid UUIDs from the client; generate one if not provided
    state = candidate && UUID_RE.test(candidate) ? candidate : randomUUID();
  } catch {
    state = randomUUID();
  }

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min TTL

  await db.insert(cliAuthStates).values({ state, expiresAt });

  const base = process.env.NEXT_PUBLIC_APP_URL ?? process.env.AUTH_URL;
  if (!base) {
    return NextResponse.json(
      { error: "Server misconfiguration: NEXT_PUBLIC_APP_URL is not set" },
      { status: 500 }
    );
  }

  const authUrl = `${base}/cli-auth?state=${encodeURIComponent(state)}`;

  return NextResponse.json({ state, authUrl, expiresIn: 300 }, { status: 201 });
}
