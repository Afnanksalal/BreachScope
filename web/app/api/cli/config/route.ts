import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { userSettings } from "@/lib/schema";
import { decrypt } from "@/lib/crypto";
import { validateApiKey, unauthorized } from "@/lib/middleware-utils";
import { eq } from "drizzle-orm";

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
