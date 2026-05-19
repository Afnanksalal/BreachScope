import { NextRequest, NextResponse } from "next/server";
import { db } from "./db";
import { apiKeys } from "./schema";
import { hashApiKey } from "./crypto";
import { eq, and, isNull } from "drizzle-orm";

export interface AuthedRequest {
  userId: string;
  apiKeyId: string;
  organizationId: string | null;
  projectId: string | null;
  scopes: string[];
}

export const DEFAULT_API_KEY_SCOPES = ["scan:write", "config:read"] as const;

export async function validateApiKey(req: NextRequest): Promise<AuthedRequest | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const key = authHeader.slice(7).trim();
  if (!key) return null;

  const hash = hashApiKey(key);

  const [record] = await db
    .select({
      id:             apiKeys.id,
      userId:         apiKeys.userId,
      organizationId: apiKeys.organizationId,
      projectId:      apiKeys.projectId,
      scopes:         apiKeys.scopes,
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

  return {
    userId:         record.userId,
    apiKeyId:       record.id,
    organizationId: record.organizationId,
    projectId:      record.projectId,
    scopes:         normalizeStoredScopes(record.scopes),
  };
}

export function unauthorized(message = "Unauthorized"): NextResponse<{ error: string }> {
  return NextResponse.json({ error: message }, { status: 401 });
}

export function forbidden(message = "Forbidden"): NextResponse<{ error: string }> {
  return NextResponse.json({ error: message }, { status: 403 });
}

export function hasScope(authed: AuthedRequest, scope: string): boolean {
  return authed.scopes.includes(scope);
}

export function badRequest(message: string): NextResponse<{ error: string }> {
  return NextResponse.json({ error: message }, { status: 400 });
}

export function ok<T>(data: T): NextResponse<T> {
  return NextResponse.json(data);
}

function normalizeStoredScopes(scopes: unknown): string[] {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return [...DEFAULT_API_KEY_SCOPES];
  }
  return scopes.filter((scope): scope is string => typeof scope === "string");
}
