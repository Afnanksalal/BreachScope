import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { auditLogs, findings, integrations, projects, scans, userSettings } from "@/lib/schema";
import { decrypt } from "@/lib/crypto";
import {
  auditGitHubRepository,
  buildGitHubAuditMarkdown,
  commentOnGitHubPullRequest,
  createGitHubIssue,
  parseGitHubRepo,
  type GitHubAuditFinding,
} from "@/lib/github-audit";
import { buildGitHubAiSynthesis } from "@/lib/ai-audit";
import { canManageProject } from "@/lib/access-control";
import { dispatchScanIntegrations } from "@/lib/integration-pipeline";
import { and, eq } from "drizzle-orm";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const integrationId = stringBody(body, "integrationId");
  if (!integrationId) return NextResponse.json({ error: "integrationId required" }, { status: 400 });

  const row = await getOwnedGitHubIntegration(session.user.id, integrationId);
  if (!row) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const token = decryptOptional(row.integration.secretRef);
  if (!token) {
    return NextResponse.json({ error: "GitHub token is not configured or cannot be decrypted" }, { status: 400 });
  }

  const repoFullName = parseGitHubRepo(stringConfig(row.integration.config, "repoFullName") || row.project.repositoryUrl || "");
  if (!repoFullName) return NextResponse.json({ error: "GitHub repoFullName is not configured" }, { status: 400 });

  const prNumber = numberBody(body, "prNumber");
  const audit = await auditGitHubRepository({
    token,
    repoFullName,
    defaultBranch: stringConfig(row.integration.config, "defaultBranch") || row.project.defaultBranch,
    prNumber,
  });

  const [settings] = await db
    .select({ openaiKeyEnc: userSettings.openaiKeyEnc })
    .from(userSettings)
    .where(eq(userSettings.userId, session.user.id))
    .limit(1);

  const openaiKey = decryptOptional(settings?.openaiKeyEnc ?? null);
  const ai = await buildGitHubAiSynthesis({ audit, openaiKey });
  const startedAt = new Date();
  const counts = countFindings(audit.findings);

  const [scan] = await db
    .insert(scans)
    .values({
      userId: session.user.id,
      projectId: row.project.id,
      organizationId: row.project.organizationId,
      project: row.project.name,
      mode: "deep",
      scanMode: "breach",
      target: audit.repoFullName,
      url: audit.repositoryUrl,
      startedAt,
      completedAt: new Date(),
      findingsTotal: audit.findings.length,
      findingsCritical: counts.critical,
      findingsHigh: counts.high,
      findingsMedium: counts.medium,
      findingsLow: counts.low,
      toolsScanned: 1,
      probeData: JSON.stringify({
        services: [{
          id: "github-repository",
          name: "GitHub repository audit",
          category: "source-control",
          steps: audit.steps,
          findingsCount: audit.findings.length,
          tokensUsed: ai.tokensUsed,
        }],
      }),
      aiReport: JSON.stringify(ai.synthesis),
    })
    .returning({ id: scans.id });

  if (!scan) return NextResponse.json({ error: "Failed to create audit scan" }, { status: 500 });

  if (audit.findings.length > 0) {
    await db.insert(findings).values(audit.findings.map((finding) => ({
      scanId: scan.id,
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      description: finding.description,
      detail: finding.detail ?? null,
      remediation: finding.remediation ?? null,
      tool: finding.tool ?? "github",
      file: finding.file ?? null,
      line: finding.line ?? null,
      references: finding.references ? JSON.stringify(finding.references) : null,
      fingerprint: finding.fingerprint ?? null,
      status: "open",
      compliance: finding.compliance ?? null,
    })));
  }

  await db.insert(auditLogs).values({
    organizationId: row.project.organizationId,
    projectId: row.project.id,
    actorUserId: session.user.id,
    action: "github.audit.completed",
    targetType: "integration",
    targetId: row.integration.id,
    metadata: {
      repoFullName: audit.repoFullName,
      prNumber,
      scanId: scan.id,
      findings: counts,
    },
  });

  const scanUrl = absoluteDashboardUrl(req, scan.id);
  const integrationDeliveries = await dispatchScanIntegrations({
    userId: session.user.id,
    project: row.project,
    scan: {
      id: scan.id,
      project: row.project.name,
      mode: "deep",
      scanMode: "breach",
      target: audit.repoFullName,
      url: audit.repositoryUrl,
      findingsTotal: audit.findings.length,
      findingsCritical: counts.critical,
      findingsHigh: counts.high,
      findingsMedium: counts.medium,
      findingsLow: counts.low,
      createdAt: startedAt,
    },
    findings: audit.findings,
    origin: req.nextUrl.origin,
  });
  const delivery = await deliverAuditBackToGitHub({
    body,
    token,
    repoFullName: audit.repoFullName,
    prNumber,
    markdown: buildGitHubAuditMarkdown(audit, scanUrl),
    labels: arrayConfig(row.integration.config, "labels"),
  });

  return NextResponse.json({
    ok: true,
    scanId: scan.id,
    scanUrl,
    repo: audit.repoFullName,
    prNumber,
    findings: counts,
    totalFindings: audit.findings.length,
    delivery,
    integrationDeliveries,
  });
}

async function getOwnedGitHubIntegration(userId: string, integrationId: string) {
  const [row] = await db
    .select({
      integration: integrations,
      project: projects,
    })
    .from(integrations)
    .innerJoin(projects, eq(integrations.projectId, projects.id))
    .where(and(
      eq(integrations.id, integrationId),
      eq(integrations.provider, "github"),
    ))
    .limit(1);
  if (!row || !await canManageProject(userId, row.project.id)) return null;
  return row;
}

async function deliverAuditBackToGitHub(opts: {
  body: Record<string, unknown> | null;
  token: string;
  repoFullName: string;
  prNumber: number | null;
  markdown: string;
  labels: string[];
}): Promise<{ issue?: unknown; comment?: unknown }> {
  const delivery: { issue?: unknown; comment?: unknown } = {};
  if (opts.body?.["createIssue"] === true) {
    delivery.issue = await createGitHubIssue(
      opts.token,
      opts.repoFullName,
      "BreachScope GitHub audit",
      opts.markdown,
      opts.labels.length > 0 ? opts.labels : ["security", "breachscope"],
    );
  }

  if (opts.body?.["commentOnPr"] === true && opts.prNumber) {
    delivery.comment = await commentOnGitHubPullRequest(opts.token, opts.repoFullName, opts.prNumber, opts.markdown);
  }
  return delivery;
}

function countFindings(rows: GitHubAuditFinding[]) {
  return {
    critical: rows.filter((finding) => finding.severity === "critical").length,
    high: rows.filter((finding) => finding.severity === "high").length,
    medium: rows.filter((finding) => finding.severity === "medium").length,
    low: rows.filter((finding) => finding.severity === "low").length,
  };
}

function absoluteDashboardUrl(req: NextRequest, scanId: string): string {
  const base = process.env["NEXT_PUBLIC_APP_URL"]?.replace(/\/$/, "")
    || `${req.nextUrl.protocol}//${req.nextUrl.host}`;
  return `${base}/dashboard/scan/${scanId}`;
}

function decryptOptional(value: string | null): string | null {
  if (!value) return null;
  try { return decrypt(value); } catch { return null; }
}

function stringBody(body: Record<string, unknown> | null, key: string): string {
  const value = body?.[key];
  return typeof value === "string" ? value.trim() : "";
}

function numberBody(body: Record<string, unknown> | null, key: string): number | null {
  const value = body?.[key];
  if (typeof value === "number" && Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  }
  return null;
}

function stringConfig(config: Record<string, unknown> | null, key: string): string {
  const value = config?.[key];
  return typeof value === "string" ? value.trim() : "";
}

function arrayConfig(config: Record<string, unknown> | null, key: string): string[] {
  const value = config?.[key];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  return [];
}
