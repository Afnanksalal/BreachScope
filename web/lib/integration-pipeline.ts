import { and, asc, eq, inArray, lte, or } from "drizzle-orm";
import { db } from "./db";
import { decrypt } from "./crypto";
import { parseGitHubRepo } from "./github-audit";
import { DISPATCH_PROVIDERS, dispatchSecurityNotification, type IntegrationResult, type SecurityFindingSummary, type SecurityNotification, type SecuritySeverity } from "./integration-executors";
import { logger } from "./logger";
import { auditLogs, integrationDeliveries, integrations, projects } from "./schema";
import { getProjectForUser, getUserOrganizations, slugify } from "./access-control";

const SEVERITY_RANK: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface ScanFindingInput {
  title: string;
  severity: string;
  category: string;
  description: string;
  remediation?: string | null;
  file?: string | null;
  line?: number | null;
  tool?: string | null;
}

export interface ScanForDelivery {
  id: string;
  project: string | null;
  mode: string;
  scanMode: string;
  target?: string | null;
  url?: string | null;
  findingsTotal: number;
  findingsCritical: number;
  findingsHigh: number;
  findingsMedium: number;
  findingsLow: number;
  createdAt?: Date;
}

export type ResolvedScanProject = typeof projects.$inferSelect;

interface ResolveScanProjectInput {
  userId: string;
  apiKeyProjectId?: string | null;
  project?: string | null;
  target?: string | null;
  url?: string | null;
}

export async function resolveScanProject(input: ResolveScanProjectInput): Promise<ResolvedScanProject | null> {
  if (input.apiKeyProjectId) {
    const project = await getProjectForUser(input.userId, input.apiKeyProjectId);
    if (project) return project;
  }

  const accessibleProjects = await listAccessibleProjects(input.userId);
  const projectName = input.project?.trim();
  if (projectName) {
    const slug = slugify(projectName);
    const match = accessibleProjects.find((project) => project.slug === slug || project.name === projectName);
    if (match) return match;
  }

  const repo = parseGitHubRepo(input.url || input.target || "");
  if (repo) {
    const match = accessibleProjects.find((project) => parseGitHubRepo(project.repositoryUrl || "") === repo);
    if (match) return match;
  }

  return null;
}

async function listAccessibleProjects(userId: string): Promise<ResolvedScanProject[]> {
  const orgs = await getUserOrganizations(userId);
  const orgIds = orgs.map((org) => org.id);
  return db
    .select()
    .from(projects)
    .where(orgIds.length > 0 ? or(eq(projects.ownerUserId, userId), inArray(projects.organizationId, orgIds)) : eq(projects.ownerUserId, userId))
    .limit(200);
}

export async function dispatchScanIntegrations(input: {
  userId: string;
  project: ResolvedScanProject | null;
  scan: ScanForDelivery;
  findings: ScanFindingInput[];
  origin: string;
}): Promise<IntegrationResult[]> {
  const { project, scan } = input;
  if (!project?.id) return [];

  const rows = await db
    .select()
    .from(integrations)
    .where(and(eq(integrations.projectId, project.id), eq(integrations.enabled, true)));

  const eligible = rows.filter((integration) => DISPATCH_PROVIDERS.has(integration.provider));
  if (eligible.length === 0) return [];

  const notification = buildScanNotification({
    projectName: project.name,
    scan,
    findings: input.findings,
    url: `${input.origin.replace(/\/$/, "")}/dashboard/scan/${scan.id}`,
  });

  const results: IntegrationResult[] = [];
  for (const integration of eligible) {
    if (!shouldDispatch(integration.config ?? {}, notification.severity)) {
      const skipped = await createDeliveryRecord({
        integration,
        scan,
        notification,
        status: "skipped",
        result: { provider: integration.provider, ok: true, status: 204, action: "skipped", skipped: true, error: "Below configured severity threshold." },
      });
      results.push(skipped);
      continue;
    }

    const deliveryId = await createPendingDelivery(integration, scan, notification);
    const result = await attemptDelivery(deliveryId);
    results.push(result);
  }

  await db.insert(auditLogs).values({
    organizationId: project.organizationId,
    projectId: project.id,
    actorUserId: input.userId,
    action: "scan.integrations.dispatched",
    targetType: "scan",
    targetId: scan.id,
    metadata: {
      total: results.length,
      delivered: results.filter((result) => result.ok && !result.skipped).length,
      failed: results.filter((result) => !result.ok).length,
      skipped: results.filter((result) => result.skipped).length,
    },
  });

  return results;
}

export async function retryDueIntegrationDeliveries(limit = 25): Promise<IntegrationResult[]> {
  const due = await db
    .select()
    .from(integrationDeliveries)
    .where(and(
      or(eq(integrationDeliveries.status, "pending"), eq(integrationDeliveries.status, "retrying")),
      lte(integrationDeliveries.nextAttemptAt, new Date()),
    ))
    .orderBy(asc(integrationDeliveries.nextAttemptAt))
    .limit(limit);

  const results: IntegrationResult[] = [];
  for (const delivery of due) {
    results.push(await attemptDelivery(delivery.id));
  }
  return results;
}

export async function getRecentIntegrationDeliveries(projectId: string, limit = 50) {
  return db
    .select()
    .from(integrationDeliveries)
    .where(eq(integrationDeliveries.projectId, projectId))
    .orderBy(asc(integrationDeliveries.createdAt))
    .limit(limit);
}

async function attemptDelivery(deliveryId: string): Promise<IntegrationResult> {
  const [delivery] = await db
    .select()
    .from(integrationDeliveries)
    .where(eq(integrationDeliveries.id, deliveryId))
    .limit(1);

  if (!delivery) return { provider: "unknown", ok: false, status: 404, action: "skipped", error: "Delivery not found" };
  if (!delivery.integrationId) return markDeliveryFailed(delivery, { provider: delivery.provider, ok: false, status: 410, action: "skipped", error: "Integration was deleted" });

  const [integration] = await db
    .select()
    .from(integrations)
    .where(eq(integrations.id, delivery.integrationId))
    .limit(1);

  if (!integration || integration.enabled === false) {
    return markDeliverySkipped(delivery, "Integration is disabled or missing.");
  }

  const notification = delivery.payload as unknown as SecurityNotification;
  const secret = integration.secretRef ? safeDecrypt(integration.secretRef, delivery.id) : null;
  const result: IntegrationResult = await dispatchSecurityNotification({
    provider: integration.provider,
    name: integration.name,
    config: integration.config,
    secret,
  }, notification).catch((error: unknown) => ({
    provider: integration.provider,
    ok: false,
    status: 500,
    action: "notification" as const,
    error: error instanceof Error ? error.message : "Delivery failed",
  }));

  if (result.skipped) return markDeliverySkipped(delivery, result.error || "Skipped by provider configuration.", result);
  if (result.ok) return markDeliveryDelivered(delivery, result);
  return markDeliveryFailed(delivery, result);
}

async function createPendingDelivery(
  integration: typeof integrations.$inferSelect,
  scan: ScanForDelivery,
  notification: SecurityNotification,
): Promise<string> {
  const [delivery] = await db
    .insert(integrationDeliveries)
    .values({
      organizationId: integration.organizationId,
      projectId: integration.projectId,
      integrationId: integration.id,
      scanId: scan.id,
      provider: integration.provider,
      action: "notify",
      status: "pending",
      attempts: 0,
      maxAttempts: 3,
      nextAttemptAt: new Date(),
      payload: notification as unknown as Record<string, unknown>,
    })
    .returning({ id: integrationDeliveries.id });
  if (!delivery) throw new Error("Failed to create integration delivery");
  return delivery.id;
}

async function createDeliveryRecord(input: {
  integration: typeof integrations.$inferSelect;
  scan: ScanForDelivery;
  notification: SecurityNotification;
  status: "skipped";
  result: IntegrationResult;
}): Promise<IntegrationResult> {
  await db.insert(integrationDeliveries).values({
    organizationId: input.integration.organizationId,
    projectId: input.integration.projectId,
    integrationId: input.integration.id,
    scanId: input.scan.id,
    provider: input.integration.provider,
    action: input.result.action,
    status: input.status,
    attempts: 0,
    maxAttempts: 3,
    lastError: input.result.error,
    payload: input.notification as unknown as Record<string, unknown>,
  });
  return input.result;
}

async function markDeliveryDelivered(delivery: typeof integrationDeliveries.$inferSelect, result: IntegrationResult): Promise<IntegrationResult> {
  await db
    .update(integrationDeliveries)
    .set({
      status: "delivered",
      attempts: (delivery.attempts ?? 0) + 1,
      deliveredAt: new Date(),
      externalUrl: result.externalUrl ?? null,
      lastError: null,
      updatedAt: new Date(),
    })
    .where(eq(integrationDeliveries.id, delivery.id));

  await writeDeliveryAudit(delivery, "integration.delivery.delivered", result);
  logger.info("integration.delivery.delivered", { deliveryId: delivery.id, provider: delivery.provider, scanId: delivery.scanId });
  return result;
}

async function markDeliveryFailed(delivery: typeof integrationDeliveries.$inferSelect, result: IntegrationResult): Promise<IntegrationResult> {
  const attempts = (delivery.attempts ?? 0) + 1;
  const maxAttempts = delivery.maxAttempts ?? 3;
  const retrying = attempts < maxAttempts;
  await db
    .update(integrationDeliveries)
    .set({
      status: retrying ? "retrying" : "failed",
      attempts,
      nextAttemptAt: retrying ? retryAt(attempts) : null,
      lastError: result.error ?? `Provider returned HTTP ${result.status}`,
      updatedAt: new Date(),
    })
    .where(eq(integrationDeliveries.id, delivery.id));

  await writeDeliveryAudit(delivery, retrying ? "integration.delivery.retrying" : "integration.delivery.failed", result);
  logger.warn("integration.delivery.failed", { deliveryId: delivery.id, provider: delivery.provider, scanId: delivery.scanId, status: result.status, error: result.error });
  return result;
}

async function markDeliverySkipped(delivery: typeof integrationDeliveries.$inferSelect, reason: string, result?: IntegrationResult): Promise<IntegrationResult> {
  const skipped = result ?? { provider: delivery.provider, ok: true, status: 204, action: "skipped" as const, skipped: true, error: reason };
  await db
    .update(integrationDeliveries)
    .set({
      status: "skipped",
      lastError: reason,
      updatedAt: new Date(),
    })
    .where(eq(integrationDeliveries.id, delivery.id));
  await writeDeliveryAudit(delivery, "integration.delivery.skipped", skipped);
  return skipped;
}

async function writeDeliveryAudit(delivery: typeof integrationDeliveries.$inferSelect, action: string, result: IntegrationResult): Promise<void> {
  await db.insert(auditLogs).values({
    organizationId: delivery.organizationId,
    projectId: delivery.projectId,
    action,
    targetType: "integration_delivery",
    targetId: delivery.id,
    metadata: {
      provider: delivery.provider,
      scanId: delivery.scanId,
      status: result.status,
      externalUrl: result.externalUrl,
      error: result.error,
    },
  });
}

function buildScanNotification(input: {
  projectName: string;
  scan: ScanForDelivery;
  findings: ScanFindingInput[];
  url: string;
}): SecurityNotification {
  const severity = highestSeverity(input.findings);
  const counts = {
    total: input.scan.findingsTotal,
    critical: input.scan.findingsCritical,
    high: input.scan.findingsHigh,
    medium: input.scan.findingsMedium,
    low: input.scan.findingsLow,
  };
  const title = input.scan.findingsTotal > 0
    ? `${severity.toUpperCase()} findings in ${input.projectName}`
    : `Clean scan for ${input.projectName}`;
  const topFindings = input.findings
    .map(normalizeFinding)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, 10);

  return {
    project: input.projectName,
    scanId: input.scan.id,
    title,
    severity,
    summary: input.scan.findingsTotal > 0
      ? `${input.scan.findingsTotal} finding(s) detected: ${input.scan.findingsCritical} critical, ${input.scan.findingsHigh} high, ${input.scan.findingsMedium} medium, ${input.scan.findingsLow} low.`
      : "No findings were detected in the completed scan.",
    url: input.url,
    target: input.scan.target || input.scan.url || null,
    mode: input.scan.mode,
    scanMode: input.scan.scanMode,
    counts,
    findings: topFindings,
    createdAt: (input.scan.createdAt ?? new Date()).toISOString(),
  };
}

function normalizeFinding(finding: ScanFindingInput): SecurityFindingSummary {
  return {
    title: finding.title,
    severity: normalizeSeverity(finding.severity),
    category: finding.category,
    description: finding.description,
    remediation: finding.remediation ?? null,
    file: finding.file ?? null,
    line: finding.line ?? null,
    tool: finding.tool ?? null,
  };
}

function highestSeverity(findings: ScanFindingInput[]): SecuritySeverity {
  return findings.reduce<SecuritySeverity>((highest, finding) => {
    const severity = normalizeSeverity(finding.severity);
    return SEVERITY_RANK[severity] > SEVERITY_RANK[highest] ? severity : highest;
  }, "info");
}

function normalizeSeverity(value: string): SecuritySeverity {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info" ? value : "info";
}

function shouldDispatch(config: Record<string, unknown>, severity: SecuritySeverity): boolean {
  const minimum = normalizeSeverity(typeof config["minimumSeverity"] === "string" ? config["minimumSeverity"] : "high");
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum];
}

function retryAt(attempts: number): Date {
  const delayMs = Math.min(15 * 60 * 1000, 30_000 * 2 ** Math.max(0, attempts - 1));
  return new Date(Date.now() + delayMs);
}

function safeDecrypt(value: string, deliveryId: string): string | null {
  try {
    return decrypt(value);
  } catch (error) {
    logger.error("integration.secret.decrypt_failed", { deliveryId, error });
    return null;
  }
}

export async function getDeliveryCounts(projectId: string): Promise<Record<string, number>> {
  const rows = await db
    .select({ status: integrationDeliveries.status })
    .from(integrationDeliveries)
    .where(and(eq(integrationDeliveries.projectId, projectId), inArray(integrationDeliveries.status, ["pending", "retrying", "failed", "delivered", "skipped"])));
  return rows.reduce<Record<string, number>>((counts, row) => {
    counts[row.status] = (counts[row.status] ?? 0) + 1;
    return counts;
  }, {});
}
