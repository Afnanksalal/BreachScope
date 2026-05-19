import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { auditLogs, integrations, projects } from "@/lib/schema";
import { encrypt } from "@/lib/crypto";
import { parseGitHubRepo } from "@/lib/github-audit";
import { and, eq } from "drizzle-orm";

const PROVIDERS = new Set(["github", "gitlab", "bitbucket", "jira", "linear", "slack", "teams", "pagerduty", "saml", "scim"]);
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
  const config = normalizeProviderConfig(provider, rawConfig, project.repositoryUrl, project.defaultBranch);
  const validationError = validateProviderConfig(provider, config);
  if (validationError) return NextResponse.json({ error: validationError }, { status: 400 });

  const [integration] = await db
    .insert(integrations)
    .values({
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
  const config = normalizeProviderConfig(row.integration.provider, mergedConfig, row.project.repositoryUrl, row.project.defaultBranch);
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
  const [project] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.ownerUserId, userId)))
    .limit(1);
  return project;
}

async function getOwnedIntegration(userId: string, integrationId: string) {
  const [row] = await db
    .select({
      integration: integrations,
      project: projects,
    })
    .from(integrations)
    .innerJoin(projects, eq(integrations.projectId, projects.id))
    .where(and(eq(integrations.id, integrationId), eq(projects.ownerUserId, userId)))
    .limit(1);
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
    };
  }
  if (provider === "jira") {
    return {
      siteUrl: trimUrl(stringConfig(clean, "siteUrl")),
      email: stringConfig(clean, "email"),
      projectKey: stringConfig(clean, "projectKey").toUpperCase(),
      issueType: stringConfig(clean, "issueType") || "Bug",
    };
  }
  if (provider === "linear") return { teamId: stringConfig(clean, "teamId") };
  if (provider === "slack" || provider === "teams") return { channel: stringConfig(clean, "channel") };
  if (provider === "pagerduty") return { serviceName: stringConfig(clean, "serviceName") };
  if (provider === "saml") return { entityId: stringConfig(clean, "entityId"), ssoUrl: trimUrl(stringConfig(clean, "ssoUrl")) };
  if (provider === "scim") return { tenant: stringConfig(clean, "tenant") };
  return clean;
}

function validateProviderConfig(provider: string, config: Record<string, unknown>): string | null {
  if (provider === "github" && !config["repoFullName"]) return "GitHub repoFullName must be owner/repo or a GitHub URL";
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

function trimUrl(value: string): string {
  return value.replace(/\/+$/, "");
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
