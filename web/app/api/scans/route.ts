import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans, findings as findingsTable } from "@/lib/schema";
import { forbidden, hasScope, unauthorized, validateApiKey } from "@/lib/middleware-utils";
import { rateLimit } from "@/lib/rate-limit";
import { eq, desc, inArray } from "drizzle-orm";

const MAX_SCAN_PAYLOAD_BYTES = 5 * 1024 * 1024;
const MAX_FINDINGS_PER_SCAN = 5000;
const MAX_JSON_FIELD_BYTES = 500_000;
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const MODES = new Set(["basic", "major", "deep"]);
const SCAN_MODES = new Set(["all", "full", "breach", "bug", "sandbox"]);

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const limit = parseLimit(req.nextUrl.searchParams.get("limit"));

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
  detail?: string;
  remediation?: string;
  tool?: string;
  file?: string;
  line?: number;
  references?: string[];
  fingerprint?: string;
  status?: string;
  compliance?: string[];
  vexStatus?: string;
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
  riskData?: string;    // JSON string of ToolRiskEntry[]
  probeData?: string;   // JSON string of ProbeActivity
  aiReport?: string;    // JSON string of AISynthesis
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
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > MAX_SCAN_PAYLOAD_BYTES) {
    return NextResponse.json({ error: "Scan payload too large" }, { status: 413 });
  }

  const authed = await validateApiKey(req);
  if (!authed) return unauthorized();
  if (!hasScope(authed, "scan:write")) return forbidden("API key is missing scan:write scope");

  const limited = await rateLimit(`scan-ingest:${authed.apiKeyId}`, 120, 60 * 1000);
  if (!limited.ok) {
    return NextResponse.json({ error: "Too many scan uploads" }, { status: 429 });
  }

  const body: unknown = await req.json().catch(() => null);
  if (!isScanPostBody(body)) {
    return NextResponse.json({ error: "Invalid body: mode, scanMode, and startedAt are required" }, { status: 400 });
  }

  const validationError = validateScanBody(body);
  if (validationError) {
    return NextResponse.json({ error: validationError }, { status: 400 });
  }

  const rawFindings: IncomingFinding[] = Array.isArray(body.findings)
    ? body.findings.slice(0, MAX_FINDINGS_PER_SCAN).map(normalizeFinding)
    : [];

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
      riskData:         safeJsonString(body.riskData),
      probeData:        safeJsonString(body.probeData),
      aiReport:         safeJsonString(body.aiReport),
    })
    .returning({ id: scans.id });

  if (!scan) {
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
  }

  if (rawFindings.length > 0) {
    const CHUNK = 2000;
    for (let i = 0; i < rawFindings.length; i += CHUNK) {
      await db.insert(findingsTable).values(
        rawFindings.slice(i, i + CHUNK).map((f) => ({
          scanId:      scan.id,
          title:       f.title       ?? "Untitled",
          severity:    f.severity,
          category:    f.category,
          description: f.description ?? "",
          detail:      f.detail      ?? null,
          remediation: f.remediation ?? null,
          tool:        f.tool        ?? null,
          file:        f.file        ?? null,
          line:        f.line        ?? null,
          references:  f.references  ? JSON.stringify(f.references) : null,
          fingerprint: f.fingerprint ?? null,
          status:      f.status      ?? "open",
          compliance:  f.compliance  ?? null,
          vexStatus:   f.vexStatus   ?? null,
        }))
      );
    }
  }

  return NextResponse.json({ id: scan.id, ok: true }, { status: 201 });
}

function parseLimit(value: string | null): number {
  if (!value) return 20;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 20;
  return Math.max(1, Math.min(parsed, 100));
}

function validateScanBody(body: ScanPostBody): string | null {
  if (!MODES.has(body.mode)) return "Invalid mode";
  if (!SCAN_MODES.has(body.scanMode)) return "Invalid scanMode";
  if (Number.isNaN(Date.parse(body.startedAt))) return "Invalid startedAt";
  if (body.completedAt && Number.isNaN(Date.parse(body.completedAt))) return "Invalid completedAt";
  if (Array.isArray(body.findings) && body.findings.length > MAX_FINDINGS_PER_SCAN) {
    return `Too many findings; maximum is ${MAX_FINDINGS_PER_SCAN}`;
  }
  for (const field of [body.riskData, body.probeData, body.aiReport]) {
    if (typeof field === "string" && Buffer.byteLength(field, "utf-8") > MAX_JSON_FIELD_BYTES) {
      return "Embedded JSON field too large";
    }
    if (typeof field === "string") {
      try { JSON.parse(field); } catch { return "Embedded JSON field is invalid"; }
    }
  }
  return null;
}

function normalizeFinding(finding: IncomingFinding): IncomingFinding {
  const severity = SEVERITIES.has(finding.severity) ? finding.severity : "info";
  return {
    title: trimString(finding.title, 240) || "Untitled",
    severity,
    category: trimString(finding.category, 80) || "code",
    description: trimString(finding.description, 5000),
    detail: trimString(finding.detail, 10000) || undefined,
    remediation: trimString(finding.remediation, 5000) || undefined,
    tool: trimString(finding.tool, 120) || undefined,
    file: trimString(finding.file, 500) || undefined,
    line: typeof finding.line === "number" && Number.isFinite(finding.line) && finding.line > 0 ? Math.floor(finding.line) : undefined,
    references: Array.isArray(finding.references) ? finding.references.slice(0, 20).map((ref) => trimString(ref, 500)).filter(Boolean) : undefined,
    fingerprint: /^[a-f0-9]{64}$/i.test(trimString(finding.fingerprint, 64)) ? trimString(finding.fingerprint, 64).toLowerCase() : undefined,
    status: typeof finding.status === "string" ? trimString(finding.status, 40) : undefined,
    compliance: Array.isArray(finding.compliance) ? finding.compliance.slice(0, 20).map((item) => trimString(item, 120)).filter(Boolean) : undefined,
    vexStatus: typeof finding.vexStatus === "string" ? trimString(finding.vexStatus, 40) : undefined,
  };
}

function trimString(value: unknown, max: number): string {
  return typeof value === "string" ? value.slice(0, max) : "";
}

function safeJsonString(value: string | undefined): string | null {
  if (!value) return null;
  return value.slice(0, MAX_JSON_FIELD_BYTES);
}

export async function DELETE(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const userScans = await db
    .select({ id: scans.id })
    .from(scans)
    .where(eq(scans.userId, session.user.id));

  if (userScans.length > 0) {
    const ids = userScans.map((s) => s.id);
    await db.delete(findingsTable).where(inArray(findingsTable.scanId, ids));
    await db.delete(scans).where(eq(scans.userId, session.user.id));
  }

  return NextResponse.json({ ok: true, deleted: userScans.length });
}
