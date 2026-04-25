import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { userSettings } from "@/lib/schema";
import { decrypt } from "@/lib/crypto";
import { validateApiKey, unauthorized } from "@/lib/middleware-utils";
import { eq } from "drizzle-orm";

const VALID_MODES      = ["basic", "major", "deep"] as const;
const VALID_SCAN_MODES = ["all", "breach", "bug"]   as const;

interface ConfigResponse {
  openaiKey: string | null;
  firecrawlKey: string | null;
  defaultMode: string;
  defaultScanMode: string;
}

export async function GET(req: NextRequest): Promise<NextResponse<ConfigResponse | { error: string }>> {
  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();

  const [row] = await db
    .select({
      openaiKeyEnc:    userSettings.openaiKeyEnc,
      firecrawlKeyEnc: userSettings.firecrawlKeyEnc,
      defaultMode:     userSettings.defaultMode,
      defaultScanMode: userSettings.defaultScanMode,
    })
    .from(userSettings)
    .where(eq(userSettings.userId, authed.userId))
    .limit(1);

  if (!row) {
    return NextResponse.json({
      openaiKey:       null,
      firecrawlKey:    null,
      defaultMode:     "basic",
      defaultScanMode: "all",
    });
  }

  let openaiKey: string | null = null;
  let firecrawlKey: string | null = null;

  try { if (row.openaiKeyEnc)    openaiKey    = decrypt(row.openaiKeyEnc);    } catch { /* bad enc */ }
  try { if (row.firecrawlKeyEnc) firecrawlKey = decrypt(row.firecrawlKeyEnc); } catch { /* bad enc */ }

  return NextResponse.json({
    openaiKey,
    firecrawlKey,
    defaultMode:     row.defaultMode     ?? "basic",
    defaultScanMode: row.defaultScanMode ?? "all",
  });
}

export async function PATCH(req: NextRequest): Promise<NextResponse> {
  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return NextResponse.json({ error: "Invalid body" }, { status: 400 });

  const updates: Partial<typeof userSettings.$inferInsert> = {
    userId:    authed.userId,
    updatedAt: new Date(),
  };

  if (typeof body.defaultMode === "string" && (VALID_MODES as readonly string[]).includes(body.defaultMode)) {
    updates.defaultMode = body.defaultMode;
  }
  if (typeof body.defaultScanMode === "string" && (VALID_SCAN_MODES as readonly string[]).includes(body.defaultScanMode)) {
    updates.defaultScanMode = body.defaultScanMode;
  }

  if (!updates.defaultMode && !updates.defaultScanMode) {
    return NextResponse.json({ error: "Nothing to update" }, { status: 400 });
  }

  await db
    .insert(userSettings)
    .values(updates as typeof userSettings.$inferInsert)
    .onConflictDoUpdate({ target: userSettings.userId, set: updates });

  return NextResponse.json({ ok: true });
}
