import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { auditLogs, integrations, projects } from "@/lib/schema";
import { encrypt } from "@/lib/crypto";
import { parseGitHubRepo } from "@/lib/github-audit";
import { canManageProject, getProjectForUser } from "@/lib/access-control";
import { normalizeOutboundUrl } from "@/lib/outbound-url";
import { eq } from "drizzle-orm";

const IDENTITY_PROVIDERS = process.env.ENABLE_IDENTITY_INTEGRATIONS === "true" ? ["saml", "scim"] : [];
const PROVIDERS = new Set(["github", "gitlab", "bitbucket", "jira", "linear", "slack", "teams", "pagerduty", ...IDENTITY_PROVIDERS]);
const SECRET_KEYS = new Set(["secret", "token", "apiToken", "webhookUrl", "routingKey", "accessToken", "pat"]);

interface SanitizedIntegration {
  id: string;
  organizationId: string | null;
  projectId: string | null;
  provider: string;
  name: string;
  enabled: boolean;
  config: Record<string, unknown> | null;
  hasSecret: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const projectId = req.nextUrl.searchParams.get("projectId");
  if (!projectId) return NextResponse.json([]);
  if (!await ownsProject(session.user.id, projectId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const rows = await db
    .select()
    .from(integrations)
    .where(eq(integrations.projectId, projectId));

  return NextResponse.json(rows.map(sanitizeIntegration));
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const projectId = stringBody(body, "projectId");
  const provider = stringBody(body, "provider").toLowerCase();
  const name = (stringBody(body, "name") || labelForProvider(provider)).slice(0, 120);
  const enabled = body?.["enabled"] !== false;

  if (!projectId || !PROVIDERS.has(provider)) {
    return NextResponse.json({ error: "Valid projectId and provider required" }, { status: 400 });
  }

  const project = await getOwnedProject(session.user.id, projectId);
  if (!project) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const rawConfig = objectBody(body, "config");
  const secret = extractSecret(body, rawConfig);
  const config = tryNormalizeProviderConfig(provider, rawConfig, project.repositoryUrl, project.defaultBranch);
  if (isConfigError(config)) return NextResponse.json({ error: config.error }, { status: 400 });
  const validationError = validateProviderConfig(provider, config);
  if (validationError) return NextResponse.json({ error: validationError }, { status: 400 });

  const [integration] = await db
    .insert(integrations)
    .values({
      organizationId: project.organizationId,
      projectId,
      provider,
      name,
      config,
      secretRef: secret ? encrypt(secret) : null,
      enabled,
    })
    .returning();

  if (!integration) return NextResponse.json({ error: "Failed to create integration" }, { status: 500 });

  await writeAuditLog(session.user.id, projectId, "integration.created", integration.id, { provider });

  return NextResponse.json(sanitizeIntegration(integration), { status: 201 });
}

export async function PATCH(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const integrationId = stringBody(body, "id");
  if (!integrationId) return NextResponse.json({ error: "Integration id required" }, { status: 400 });

  const row = await getOwnedIntegration(session.user.id, integrationId);
  if (!row) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const rawConfig = objectBody(body, "config");
  const mergedConfig = { ...(row.integration.config ?? {}), ...rawConfig };
  const secret = extractSecret(body, rawConfig);
  const config = tryNormalizeProviderConfig(row.integration.provider, mergedConfig, row.project.repositoryUrl, row.project.defaultBranch);
  if (isConfigError(config)) return NextResponse.json({ error: config.error }, { status: 400 });
  const validationError = validateProviderConfig(row.integration.provider, config);
  if (validationError) return NextResponse.json({ error: validationError }, { status: 400 });

  const update: Partial<typeof integrations.$inferInsert> = {
    name: stringBody(body, "name").slice(0, 120) || row.integration.name,
    enabled: typeof body?.["enabled"] === "boolean" ? body["enabled"] : row.integration.enabled,
    config,
    updatedAt: new Date(),
  };
  if (secret) update.secretRef = encrypt(secret);

  const [integration] = await db
    .update(integrations)
    .set(update)
    .where(eq(integrations.id, integrationId))
    .returning();

  if (!integration) return NextResponse.json({ error: "Failed to update integration" }, { status: 500 });

  await writeAuditLog(session.user.id, row.project.id, "integration.updated", integrationId, { provider: row.integration.provider });

  return NextResponse.json(sanitizeIntegration(integration));
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  const integrationId = stringBody(body, "id") || req.nextUrl.searchParams.get("id") || "";
  if (!integrationId) return NextResponse.json({ error: "Integration id required" }, { status: 400 });

  const row = await getOwnedIntegration(session.user.id, integrationId);
  if (!row) return NextResponse.json({ error: "Not found" }, { status: 404 });

  await db.delete(integrations).where(eq(integrations.id, integrationId));
  await writeAuditLog(session.user.id, row.project.id, "integration.deleted", integrationId, { provider: row.integration.provider });

  return NextResponse.json({ ok: true });
}

async function ownsProject(userId: string, projectId: string): Promise<boolean> {
  return Boolean(await getOwnedProject(userId, projectId));
}

async function getOwnedProject(userId: string, projectId: string) {
  if (!await canManageProject(userId, projectId)) return null;
  return getProjectForUser(userId, projectId);
}

async function getOwnedIntegration(userId: string, integrationId: string) {
  const [row] = await db
    .select({
      integration: integrations,
      project: projects,
    })
    .from(integrations)
    .innerJoin(projects, eq(integrations.projectId, projects.id))
    .where(eq(integrations.id, integrationId))
    .limit(1);
  if (!row || !row.project.id || !await canManageProject(userId, row.project.id)) return null;
  return row;
}

async function writeAuditLog(actorUserId: string, projectId: string, action: string, targetId: string, metadata: Record<string, unknown>): Promise<void> {
  await db.insert(auditLogs).values({
    projectId,
    actorUserId,
    action,
    targetType: "integration",
    targetId,
    metadata,
  });
}

function sanitizeIntegration(row: typeof integrations.$inferSelect): SanitizedIntegration {
  return {
    id: row.id,
    organizationId: row.organizationId,
    projectId: row.projectId,
    provider: row.provider,
    name: row.name,
    enabled: row.enabled,
    config: removeSecretKeys(row.config ?? {}),
    hasSecret: Boolean(row.secretRef),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function normalizeProviderConfig(
  provider: string,
  config: Record<string, unknown>,
  projectRepositoryUrl?: string | null,
  projectDefaultBranch?: string | null,
): Record<string, unknown> {
  const clean = removeSecretKeys(config);
  if (provider === "github") {
    const repoFullName = parseGitHubRepo(stringConfig(clean, "repoFullName") || projectRepositoryUrl || "");
    return {
      repoFullName,
      defaultBranch: stringConfig(clean, "defaultBranch") || projectDefaultBranch || "main",
      createIssues: clean["createIssues"] === true,
      labels: arrayConfig(clean, "labels").slice(0, 10),
      minimumSeverity: severityConfig(clean),
    };
  }
  if (provider === "gitlab") {
    return {
      instanceUrl: normalizeHttpsConfig(stringConfig(clean, "instanceUrl") || "https://gitlab.com", "GitLab instance URL"),
      projectPath: stringConfig(clean, "projectPath") || parseGitHubRepo(projectRepositoryUrl || ""),
      createIssues: clean["createIssues"] !== false,
      labels: arrayConfig(clean, "labels").slice(0, 10),
      minimumSeverity: severityConfig(clean),
    };
  }
  if (provider === "bitbucket") {
    const repo = parseRepoParts(stringConfig(clean, "repoFullName") || projectRepositoryUrl || "");
    return {
      workspace: stringConfig(clean, "workspace") || repo.owner,
      repoSlug: stringConfig(clean, "repoSlug") || repo.repo,
      username: stringConfig(clean, "username"),
      createIssues: clean["createIssues"] !== false,
      minimumSeverity: severityConfig(clean),
    };
  }
  if (provider === "jira") {
    return {
      siteUrl: normalizeHttpsConfig(stringConfig(clean, "siteUrl"), "Jira site URL"),
      email: stringConfig(clean, "email"),
      projectKey: stringConfig(clean, "projectKey").toUpperCase(),
      issueType: stringConfig(clean, "issueType") || "Bug",
      priorityName: stringConfig(clean, "priorityName"),
      labels: arrayConfig(clean, "labels").slice(0, 10),
      minimumSeverity: severityConfig(clean),
    };
  }
  if (provider === "linear") {
    return {
      teamId: stringConfig(clean, "teamId"),
      projectId: stringConfig(clean, "projectId"),
      labelIds: arrayConfig(clean, "labelIds").slice(0, 10),
      priority: numberConfig(clean, "priority"),
      minimumSeverity: severityConfig(clean),
    };
  }
  if (provider === "slack" || provider === "teams") return { channel: stringConfig(clean, "channel"), minimumSeverity: severityConfig(clean) };
  if (provider === "pagerduty") return { serviceName: stringConfig(clean, "serviceName"), minimumSeverity: severityConfig(clean) };
  if (provider === "saml") return { entityId: stringConfig(clean, "entityId"), ssoUrl: trimUrl(stringConfig(clean, "ssoUrl")) };
  if (provider === "scim") return { tenant: stringConfig(clean, "tenant") };
  return clean;
}

function tryNormalizeProviderConfig(
  provider: string,
  config: Record<string, unknown>,
  projectRepositoryUrl?: string | null,
  projectDefaultBranch?: string | null,
): Record<string, unknown> | { error: string } {
  try {
    return normalizeProviderConfig(provider, config, projectRepositoryUrl, projectDefaultBranch);
  } catch (error) {
    return { error: error instanceof Error ? error.message : "Invalid integration configuration" };
  }
}

function isConfigError(value: Record<string, unknown> | { error: string }): value is { error: string } {
  return typeof (value as { error?: unknown }).error === "string" && Object.keys(value).length === 1;
}

function validateProviderConfig(provider: string, config: Record<string, unknown>): string | null {
  if (provider === "github" && !config["repoFullName"]) return "GitHub repoFullName must be owner/repo or a GitHub URL";
  if (provider === "gitlab" && !config["projectPath"]) return "GitLab requires a project path or project ID";
  if (provider === "bitbucket" && (!config["workspace"] || !config["repoSlug"])) return "Bitbucket requires workspace and repoSlug";
  if (provider === "jira" && (!config["siteUrl"] || !config["email"] || !config["projectKey"])) {
    return "Jira requires siteUrl, email, and projectKey";
  }
  if (provider === "linear" && !config["teamId"]) return "Linear requires teamId";
  return null;
}

function extractSecret(body: Record<string, unknown> | null, config: Record<string, unknown>): string {
  for (const key of SECRET_KEYS) {
    const topLevel = body?.[key];
    if (typeof topLevel === "string" && topLevel.trim()) return topLevel.trim();
    const nested = config[key];
    if (typeof nested === "string" && nested.trim()) return nested.trim();
  }
  return "";
}

function objectBody(body: Record<string, unknown> | null, key: string): Record<string, unknown> {
  const value = body?.[key];
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stringBody(body: Record<string, unknown> | null, key: string): string {
  const value = body?.[key];
  return typeof value === "string" ? value.trim() : "";
}

function stringConfig(config: Record<string, unknown>, key: string): string {
  const value = config[key];
  return typeof value === "string" ? value.trim().slice(0, 500) : "";
}

function arrayConfig(config: Record<string, unknown>, key: string): string[] {
  const value = config[key];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  if (typeof value === "string") return value.split(",").map((item) => item.trim()).filter(Boolean);
  return [];
}

function numberConfig(config: Record<string, unknown>, key: string): number | undefined {
  const value = config[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function severityConfig(config: Record<string, unknown>): string {
  const severity = stringConfig(config, "minimumSeverity").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(severity) ? severity : "high";
}

function parseRepoParts(value: string): { owner: string; repo: string } {
  const trimmed = value.trim();
  const match = trimmed.match(/(?:bitbucket\.org\/)?([^/\s]+)\/([^/\s#?]+)/i);
  return { owner: match?.[1] ?? "", repo: match?.[2]?.replace(/\.git$/, "") ?? "" };
}

function trimUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

function normalizeHttpsConfig(value: string, label: string): string {
  if (!value) return "";
  return trimUrl(normalizeOutboundUrl(value, { label, requireHttps: true }));
}

function removeSecretKeys(config: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(config).filter(([key]) => !SECRET_KEYS.has(key)));
}

function labelForProvider(provider: string): string {
  const labels: Record<string, string> = {
    github: "GitHub",
    gitlab: "GitLab",
    bitbucket: "Bitbucket",
    jira: "Jira",
    linear: "Linear",
    slack: "Slack",
    teams: "Teams",
    pagerduty: "PagerDuty",
    saml: "SAML",
    scim: "SCIM",
  };
  return labels[provider] ?? provider;
}
