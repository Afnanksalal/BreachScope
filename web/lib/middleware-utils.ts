import { NextRequest, NextResponse } from "next/server";
import { db } from "./db";
import { apiKeys } from "./schema";
import { hashApiKey } from "./crypto";
import { eq, and, isNull } from "drizzle-orm";

export interface AuthedRequest {
  userId: string;
  apiKeyId: string;
}

export async function validateApiKey(req: NextRequest): Promise<AuthedRequest | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const key = authHeader.slice(7).trim();
  if (!key) return null;

  const hash = hashApiKey(key);

  const [record] = await db
    .select({
      id:     apiKeys.id,
      userId: apiKeys.userId,
    })
    .from(apiKeys)
    .where(and(eq(apiKeys.keyHash, hash), isNull(apiKeys.revokedAt)))
    .limit(1);

  if (!record) return null;

  // Fire-and-forget last-used update — intentionally unawaited
  void db
    .update(apiKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiKeys.id, record.id));

  return { userId: record.userId, apiKeyId: record.id };
}

export function unauthorized(message = "Unauthorized"): NextResponse<{ error: string }> {
  return NextResponse.json({ error: message }, { status: 401 });
}

export function badRequest(message: string): NextResponse<{ error: string }> {
  return NextResponse.json({ error: message }, { status: 400 });
}

export function ok<T>(data: T): NextResponse<T> {
  return NextResponse.json(data);
}
