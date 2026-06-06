import type { NextRequest } from "next/server";

interface Bucket {
  count: number;
  resetAt: number;
}

export interface RateLimitResult {
  ok: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

export function clientIp(req: NextRequest): string {
  const platformIp =
    req.headers.get("x-vercel-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("cf-connecting-ip")?.trim() ||
    req.headers.get("fly-client-ip")?.trim() ||
    req.headers.get("x-real-ip")?.trim();
  if (platformIp) return platformIp;
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
}

export async function rateLimit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const result = await upstashRateLimit(key, limit, windowMs).catch(() => null);
    if (result) return result;
  }
  return memoryRateLimit(key, limit, windowMs);
}

function memoryRateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || bucket.resetAt <= now) {
    const next = { count: 1, resetAt: now + windowMs };
    buckets.set(key, next);
    return { ok: true, limit, remaining: limit - 1, resetAt: next.resetAt };
  }

  bucket.count += 1;
  const remaining = Math.max(0, limit - bucket.count);
  return {
    ok: bucket.count <= limit,
    limit,
    remaining,
    resetAt: bucket.resetAt,
  };
}

async function upstashRateLimit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
  const base = process.env.UPSTASH_REDIS_REST_URL!;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN!;
  const redisKey = `breachscope:rl:${key}`;
  const now = Date.now();
  const resetAt = now + windowMs;

  const res = await fetch(`${base}/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify([
      ["INCR", redisKey],
      ["PEXPIRE", redisKey, String(windowMs), "NX"],
      ["PTTL", redisKey],
    ]),
    cache: "no-store",
  });

  if (!res.ok) throw new Error("rate-limit backend unavailable");
  const data = await res.json() as Array<{ result: unknown }>;
  const count = Number(data[0]?.result ?? 1);
  const ttl = Number(data[2]?.result ?? windowMs);
  const effectiveResetAt = ttl > 0 ? now + ttl : resetAt;

  return {
    ok: count <= limit,
    limit,
    remaining: Math.max(0, limit - count),
    resetAt: effectiveResetAt,
  };
}

export function clearRateLimitsForTests(): void {
  buckets.clear();
}
