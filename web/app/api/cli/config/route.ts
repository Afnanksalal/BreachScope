import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { userSettings } from "@/lib/schema";
import { decrypt } from "@/lib/crypto";
import { forbidden, hasScope, unauthorized, validateApiKey } from "@/lib/middleware-utils";
import { eq } from "drizzle-orm";

const VALID_MODES      = ["basic", "major", "deep"] as const;
const VALID_SCAN_MODES = ["all", "full", "breach", "bug"]   as const;

interface ConfigResponse {
  openaiKey: string | null;
  firecrawlKey: string | null;
  defaultMode: string;
  defaultScanMode: string;
  sandboxScanMode: string;
  sandboxDeep: boolean;
}

export async function GET(req: NextRequest): Promise<NextResponse<ConfigResponse | { error: string }>> {
  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();
  if (!hasScope(authed, "config:read")) return forbidden("API key is missing config:read scope");

  const [row] = await db
    .select({
      openaiKeyEnc:    userSettings.openaiKeyEnc,
      firecrawlKeyEnc: userSettings.firecrawlKeyEnc,
      defaultMode:     userSettings.defaultMode,
      defaultScanMode: userSettings.defaultScanMode,
      sandboxScanMode: userSettings.sandboxScanMode,
      sandboxDeep:     userSettings.sandboxDeep,
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
      sandboxScanMode: "all",
      sandboxDeep:     false,
    });
  }

  let openaiKey: string | null = null;
  let firecrawlKey: string | null = null;
  const canReadSecrets = authed.scopes.includes("secrets:read");

  try { if (canReadSecrets && row.openaiKeyEnc)    openaiKey    = decrypt(row.openaiKeyEnc);    } catch { /* bad enc */ }
  try { if (canReadSecrets && row.firecrawlKeyEnc) firecrawlKey = decrypt(row.firecrawlKeyEnc); } catch { /* bad enc */ }

  return NextResponse.json({
    openaiKey,
    firecrawlKey,
    defaultMode:     row.defaultMode     ?? "basic",
    defaultScanMode: row.defaultScanMode ?? "all",
    sandboxScanMode: row.sandboxScanMode ?? "all",
    sandboxDeep:     row.sandboxDeep === "true",
  });
}

export async function PATCH(req: NextRequest): Promise<NextResponse> {
  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();
  if (!hasScope(authed, "settings:write")) return forbidden("API key is missing settings:write scope");

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
  if (typeof body.sandboxScanMode === "string" && (VALID_SCAN_MODES as readonly string[]).includes(body.sandboxScanMode)) {
    updates.sandboxScanMode = body.sandboxScanMode;
  }
  if (typeof body.sandboxDeep === "boolean") {
    updates.sandboxDeep = body.sandboxDeep ? "true" : "false";
  }

  if (!updates.defaultMode && !updates.defaultScanMode && !updates.sandboxScanMode && updates.sandboxDeep === undefined) {
    return NextResponse.json({ error: "Nothing to update" }, { status: 400 });
  }

  await db
    .insert(userSettings)
    .values(updates as typeof userSettings.$inferInsert)
    .onConflictDoUpdate({ target: userSettings.userId, set: updates });

  return NextResponse.json({ ok: true });
}
