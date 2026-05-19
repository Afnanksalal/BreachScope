import { NextRequest, NextResponse } from "next/server";
import { retryDueIntegrationDeliveries } from "@/lib/integration-pipeline";
import { logger } from "@/lib/logger";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const auth = req.headers.get("authorization") || "";
  const expected = process.env["CRON_SECRET"];

  if (expected && auth !== `Bearer ${expected}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (!expected && process.env["NODE_ENV"] === "production") {
    return NextResponse.json({ error: "CRON_SECRET is required in production" }, { status: 503 });
  }

  const limit = Math.max(1, Math.min(Number(req.nextUrl.searchParams.get("limit") ?? 25), 100));
  const results = await retryDueIntegrationDeliveries(limit);
  logger.info("integration.delivery.retry_job.completed", {
    total: results.length,
    delivered: results.filter((result) => result.ok && !result.skipped).length,
    failed: results.filter((result) => !result.ok).length,
  });

  return NextResponse.json({ ok: true, results });
}

export const POST = GET;
