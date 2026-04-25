import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { cliAuthStates } from "@/lib/schema";
import { randomUUID } from "crypto";

export async function POST(req: NextRequest) {
  let state: string;
  try {
    const body = await req.json();
    state = (typeof body.state === "string" && body.state.length > 0) ? body.state : randomUUID();
  } catch {
    state = randomUUID();
  }

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await db.insert(cliAuthStates).values({ state, expiresAt });

  const base = process.env.NEXT_PUBLIC_APP_URL ?? process.env.AUTH_URL;
  if (!base) {
    return NextResponse.json(
      { error: "Server misconfiguration: NEXT_PUBLIC_APP_URL is not set" },
      { status: 500 },
    );
  }
  const authUrl = `${base}/cli-auth?state=${state}`;

  return NextResponse.json({ state, authUrl, expiresIn: 300 }, { status: 201 });
}
