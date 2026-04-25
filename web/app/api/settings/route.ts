import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { userSettings } from "@/lib/schema";
import { encrypt } from "@/lib/crypto";
import { eq } from "drizzle-orm";

export interface SettingsResponse {
  hasOpenAI: boolean;
  hasFirecrawl: boolean;
  defaultMode: string;
  defaultScanMode: string;
}

export async function GET(): Promise<NextResponse<SettingsResponse | { error: string }>> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const [row] = await db
    .select({
      openaiKeyEnc:    userSettings.openaiKeyEnc,
      firecrawlKeyEnc: userSettings.firecrawlKeyEnc,
      defaultMode:     userSettings.defaultMode,
      defaultScanMode: userSettings.defaultScanMode,
    })
    .from(userSettings)
    .where(eq(userSettings.userId, session.user.id))
    .limit(1);

  return NextResponse.json({
    hasOpenAI:       !!row?.openaiKeyEnc,
    hasFirecrawl:    !!row?.firecrawlKeyEnc,
    defaultMode:     row?.defaultMode     ?? "basic",
    defaultScanMode: row?.defaultScanMode ?? "all",
  });
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body: unknown = await req.json().catch(() => null);
  if (typeof body !== "object" || body === null) {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }

  const payload = body as Record<string, unknown>;
  const updates: Partial<typeof userSettings.$inferInsert> = {
    userId:    session.user.id,
    updatedAt: new Date(),
  };

  if (typeof payload.openaiKey === "string" && payload.openaiKey.trim()) {
    updates.openaiKeyEnc = encrypt(payload.openaiKey.trim());
  }
  if (typeof payload.firecrawlKey === "string" && payload.firecrawlKey.trim()) {
    updates.firecrawlKeyEnc = encrypt(payload.firecrawlKey.trim());
  }
  if (typeof payload.defaultMode === "string" && ["basic", "major", "deep"].includes(payload.defaultMode)) {
    updates.defaultMode = payload.defaultMode;
  }
  if (typeof payload.defaultScanMode === "string" && ["all", "breach", "bug"].includes(payload.defaultScanMode)) {
    updates.defaultScanMode = payload.defaultScanMode;
  }

  await db
    .insert(userSettings)
    .values(updates as typeof userSettings.$inferInsert)
    .onConflictDoUpdate({ target: userSettings.userId, set: updates });

  return NextResponse.json({ ok: true });
}
