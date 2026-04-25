import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans, findings as findingsTable } from "@/lib/schema";
import { validateApiKey, unauthorized } from "@/lib/middleware-utils";
import { eq, desc } from "drizzle-orm";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const limitParam = req.nextUrl.searchParams.get("limit");
  const limit = Math.min(Number(limitParam ?? 20), 100);

  const rows = await db
    .select()
    .from(scans)
    .where(eq(scans.userId, session.user.id))
    .orderBy(desc(scans.createdAt))
    .limit(limit);

  return NextResponse.json(rows);
}

interface IncomingFinding {
  title: string;
  severity: string;
  category: string;
  description: string;
  remediation?: string;
  tool?: string;
  file?: string;
  line?: number;
  references?: string[];
}

interface ScanPostBody {
  project?: string;
  mode: string;
  scanMode: string;
  target?: string;
  url?: string;
  startedAt: string;
  completedAt?: string;
  findings?: IncomingFinding[];
  toolsScanned?: number;
}

function isScanPostBody(v: unknown): v is ScanPostBody {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Record<string, unknown>).mode === "string" &&
    typeof (v as Record<string, unknown>).scanMode === "string" &&
    typeof (v as Record<string, unknown>).startedAt === "string"
  );
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();

  const body: unknown = await req.json().catch(() => null);
  if (!isScanPostBody(body)) {
    return NextResponse.json({ error: "Invalid body: mode, scanMode, and startedAt are required" }, { status: 400 });
  }

  const rawFindings: IncomingFinding[] = Array.isArray(body.findings) ? body.findings : [];

  const findingsCritical = rawFindings.filter((f) => f.severity === "critical").length;
  const findingsHigh     = rawFindings.filter((f) => f.severity === "high").length;
  const findingsMedium   = rawFindings.filter((f) => f.severity === "medium").length;
  const findingsLow      = rawFindings.filter((f) => f.severity === "low").length;

  const [scan] = await db
    .insert(scans)
    .values({
      userId:           authed.userId,
      apiKeyId:         authed.apiKeyId,
      project:          body.project   ?? null,
      mode:             body.mode,
      scanMode:         body.scanMode,
      target:           body.target    ?? null,
      url:              body.url       ?? null,
      startedAt:        new Date(body.startedAt),
      completedAt:      body.completedAt ? new Date(body.completedAt) : new Date(),
      findingsTotal:    rawFindings.length,
      findingsCritical,
      findingsHigh,
      findingsMedium,
      findingsLow,
      toolsScanned:     body.toolsScanned ?? 0,
    })
    .returning({ id: scans.id });

  if (!scan) {
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
  }

  if (rawFindings.length > 0) {
    await db.insert(findingsTable).values(
      rawFindings.slice(0, 1000).map((f) => ({
        scanId:      scan.id,
        title:       f.title,
        severity:    f.severity,
        category:    f.category,
        description: f.description,
        remediation: f.remediation ?? null,
        tool:        f.tool        ?? null,
        file:        f.file        ?? null,
        line:        f.line        ?? null,
        references:  f.references  ? JSON.stringify(f.references) : null,
      }))
    );
  }

  return NextResponse.json({ id: scan.id, ok: true }, { status: 201 });
}
