import { safeOutboundFetch } from "./outbound-url";

export type SecuritySeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SecurityFindingSummary {
  title: string;
  severity: SecuritySeverity;
  category?: string;
  description?: string;
  remediation?: string | null;
  file?: string | null;
  line?: number | null;
  tool?: string | null;
}

export interface SecurityNotification {
  project: string;
  scanId?: string;
  title: string;
  severity: SecuritySeverity;
  summary: string;
  url?: string;
  target?: string | null;
  mode?: string;
  scanMode?: string;
  counts?: Partial<Record<SecuritySeverity, number>> & { total?: number };
  findings?: SecurityFindingSummary[];
  createdAt?: string;
}

export interface IntegrationConfig {
  provider: string;
  name: string;
  config: Record<string, unknown> | null;
  secret?: string | null;
}

export interface IntegrationResult {
  provider: string;
  ok: boolean;
  status: number;
  action: "notification" | "issue" | "incident" | "skipped";
  externalUrl?: string;
  externalId?: string;
  skipped?: boolean;
  error?: string;
}

export const DISPATCH_PROVIDERS = new Set(["slack", "teams", "pagerduty", "jira", "linear", "github", "gitlab", "bitbucket"]);

export async function dispatchSecurityNotification(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const provider = integration.provider.toLowerCase();
  if (provider === "slack") return postWebhook(provider, integration, slackPayload(notification));
  if (provider === "teams") return postWebhook(provider, integration, teamsPayload(notification));
  if (provider === "pagerduty") return postPagerDuty(integration, notification);
  if (provider === "jira") return postJira(integration, notification);
  if (provider === "linear") return postLinear(integration, notification);
  if (provider === "github") return postGitHubIssue(integration, notification);
  if (provider === "gitlab") return postGitLabIssue(integration, notification);
  if (provider === "bitbucket") return postBitbucketIssue(integration, notification);
  if (provider === "saml" || provider === "scim") {
    return { provider, ok: true, status: 204, action: "skipped", skipped: true, error: "Identity providers do not receive scan deliveries." };
  }
  return { provider, ok: false, status: 400, action: "skipped", error: "Unsupported integration provider" };
}

async function postWebhook(
  provider: string,
  integration: IntegrationConfig,
  payload: Record<string, unknown>,
): Promise<IntegrationResult> {
  const webhookUrl = integration.secret || stringConfig(integration.config, "webhookUrl");
  if (!webhookUrl) return { provider, ok: false, status: 400, action: "notification", error: "Missing webhookUrl" };
  try {
    const res = await safeOutboundFetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, { label: `${provider} webhook URL` });
    return { provider, ok: res.ok, status: res.status, action: "notification", error: res.ok ? undefined : await safeText(res) };
  } catch (error) {
    return { provider, ok: false, status: 400, action: "notification", error: errorMessage(error) };
  }
}

async function postPagerDuty(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const routingKey = integration.secret || stringConfig(integration.config, "routingKey");
  if (!routingKey) return { provider: "pagerduty", ok: false, status: 400, action: "incident", error: "Missing routingKey" };
  const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      routing_key: routingKey,
      event_action: "trigger",
      dedup_key: notification.scanId ? `breachscope:${notification.scanId}:${notification.severity}` : undefined,
      payload: {
        summary: notification.title,
        source: notification.project,
        severity: pagerDutySeverity(notification.severity),
        component: notification.target || notification.project,
        group: "security",
        class: notification.scanMode || "scan",
        custom_details: {
          summary: notification.summary,
          counts: notification.counts,
          findings: notification.findings?.slice(0, 10),
        },
      },
      links: notification.url ? [{ href: notification.url, text: "Open BreachScope scan" }] : [],
    }),
  });
  const body = await safeJson(res);
  return {
    provider: "pagerduty",
    ok: res.ok,
    status: res.status,
    action: "incident",
    externalId: stringValue(body?.["dedup_key"]),
    error: res.ok ? undefined : (stringValue(body?.["message"]) || await safeText(res)),
  };
}

async function postJira(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const siteUrl = stringConfig(integration.config, "siteUrl");
  const email = stringConfig(integration.config, "email");
  const apiToken = integration.secret || stringConfig(integration.config, "apiToken");
  const projectKey = stringConfig(integration.config, "projectKey");
  if (!siteUrl || !email || !apiToken || !projectKey) {
    return { provider: "jira", ok: false, status: 400, action: "issue", error: "Missing Jira siteUrl, email, apiToken, or projectKey" };
  }

  const fields: Record<string, unknown> = {
    project: { key: projectKey },
    summary: notification.title.slice(0, 240),
    description: jiraDescription(notification),
    issuetype: { name: stringConfig(integration.config, "issueType") || "Bug" },
  };
  const labels = mergeLabels(arrayConfig(integration.config, "labels"), ["breachscope", "security"]);
  if (labels.length > 0) fields["labels"] = labels;
  const priorityName = stringConfig(integration.config, "priorityName") || jiraPriority(notification.severity);
  if (priorityName) fields["priority"] = { name: priorityName };

  let res: Response;
  try {
    res = await safeOutboundFetch(`${siteUrl.replace(/\/$/, "")}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ fields }),
    }, { label: "Jira site URL" });
  } catch (error) {
    return { provider: "jira", ok: false, status: 400, action: "issue", error: errorMessage(error) };
  }
  const body = await safeJson(res);
  const key = stringValue(body?.["key"]);
  return {
    provider: "jira",
    ok: res.ok,
    status: res.status,
    action: "issue",
    externalId: key,
    externalUrl: key ? `${siteUrl.replace(/\/$/, "")}/browse/${key}` : undefined,
    error: res.ok ? undefined : (stringValue(body?.["errorMessages"]) || await safeText(res)),
  };
}

async function postLinear(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const apiKey = integration.secret || stringConfig(integration.config, "apiKey");
  const teamId = stringConfig(integration.config, "teamId");
  if (!apiKey || !teamId) return { provider: "linear", ok: false, status: 400, action: "issue", error: "Missing Linear apiKey or teamId" };

  const input: Record<string, unknown> = {
    teamId,
    title: notification.title.slice(0, 240),
    description: markdownDescription(notification),
  };
  const labelIds = arrayConfig(integration.config, "labelIds").slice(0, 10);
  if (labelIds.length > 0) input["labelIds"] = labelIds;
  const projectId = stringConfig(integration.config, "projectId");
  if (projectId) input["projectId"] = projectId;
  const priority = linearPriority(notification.severity, numberConfig(integration.config, "priority"));
  if (priority) input["priority"] = priority;

  const res = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: {
      Authorization: apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
      variables: { input },
    }),
  });
  const body = await safeJson(res);
  const issue = objectValue(objectValue(body?.["data"])?.["issueCreate"])?.["issue"] as Record<string, unknown> | undefined;
  const graphqlErrors = Array.isArray(body?.["errors"]) ? JSON.stringify(body?.["errors"]).slice(0, 500) : "";
  return {
    provider: "linear",
    ok: res.ok && objectValue(objectValue(body?.["data"])?.["issueCreate"])?.["success"] === true,
    status: res.status,
    action: "issue",
    externalId: stringValue(issue?.["identifier"]) || stringValue(issue?.["id"]),
    externalUrl: stringValue(issue?.["url"]) || undefined,
    error: res.ok ? (graphqlErrors || undefined) : (graphqlErrors || await safeText(res)),
  };
}

async function postGitHubIssue(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const repoFullName = stringConfig(integration.config, "repoFullName");
  const token = integration.secret || stringConfig(integration.config, "token");
  const createIssues = integration.config?.["createIssues"] === true;

  if (!repoFullName || !token) {
    return { provider: "github", ok: false, status: 400, action: "issue", error: "Missing GitHub repoFullName or token" };
  }
  if (!createIssues) {
    return { provider: "github", ok: true, status: 204, action: "skipped", skipped: true, error: "Issue creation is disabled for this integration." };
  }

  const res = await fetch(`https://api.github.com/repos/${repoFullName}/issues`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({
      title: notification.title.slice(0, 240),
      body: markdownDescription(notification),
      labels: mergeLabels(arrayConfig(integration.config, "labels"), ["security", "breachscope"]),
    }),
  });
  const body = await safeJson(res);

  return {
    provider: "github",
    ok: res.ok,
    status: res.status,
    action: "issue",
    externalId: stringValue(body?.["number"]),
    externalUrl: stringValue(body?.["html_url"]) || undefined,
    error: res.ok ? undefined : (stringValue(body?.["message"]) || await safeText(res)),
  };
}

async function postGitLabIssue(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const token = integration.secret || stringConfig(integration.config, "token") || stringConfig(integration.config, "accessToken");
  const projectPath = stringConfig(integration.config, "projectPath") || stringConfig(integration.config, "projectId");
  const instanceUrl = stringConfig(integration.config, "instanceUrl") || "https://gitlab.com";
  const createIssues = integration.config?.["createIssues"] !== false;
  if (!token || !projectPath) {
    return { provider: "gitlab", ok: false, status: 400, action: "issue", error: "Missing GitLab token or projectPath" };
  }
  if (!createIssues) {
    return { provider: "gitlab", ok: true, status: 204, action: "skipped", skipped: true, error: "Issue creation is disabled for this integration." };
  }

  let res: Response;
  try {
    res = await safeOutboundFetch(`${instanceUrl.replace(/\/$/, "")}/api/v4/projects/${encodeURIComponent(projectPath)}/issues`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "PRIVATE-TOKEN": token,
      },
      body: JSON.stringify({
        title: notification.title.slice(0, 240),
        description: markdownDescription(notification),
        labels: mergeLabels(arrayConfig(integration.config, "labels"), ["security", "breachscope"]).join(","),
        issue_type: "issue",
      }),
    }, { label: "GitLab instance URL" });
  } catch (error) {
    return { provider: "gitlab", ok: false, status: 400, action: "issue", error: errorMessage(error) };
  }
  const body = await safeJson(res);
  return {
    provider: "gitlab",
    ok: res.ok,
    status: res.status,
    action: "issue",
    externalId: stringValue(body?.["iid"]) || stringValue(body?.["id"]),
    externalUrl: stringValue(body?.["web_url"]) || undefined,
    error: res.ok ? undefined : (stringValue(body?.["message"]) || await safeText(res)),
  };
}

async function postBitbucketIssue(
  integration: IntegrationConfig,
  notification: SecurityNotification,
): Promise<IntegrationResult> {
  const token = integration.secret || stringConfig(integration.config, "token") || stringConfig(integration.config, "appPassword");
  const workspace = stringConfig(integration.config, "workspace");
  const repoSlug = stringConfig(integration.config, "repoSlug");
  const username = stringConfig(integration.config, "username");
  const createIssues = integration.config?.["createIssues"] !== false;
  if (!token || !workspace || !repoSlug) {
    return { provider: "bitbucket", ok: false, status: 400, action: "issue", error: "Missing Bitbucket token, workspace, or repoSlug" };
  }
  if (!createIssues) {
    return { provider: "bitbucket", ok: true, status: 204, action: "skipped", skipped: true, error: "Issue creation is disabled for this integration." };
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  headers["Authorization"] = username
    ? `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}`
    : `Bearer ${token}`;

  const res = await fetch(`https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}/issues`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      title: notification.title.slice(0, 240),
      content: { raw: markdownDescription(notification) },
      kind: "bug",
      priority: bitbucketPriority(notification.severity),
    }),
  });
  const body = await safeJson(res);
  return {
    provider: "bitbucket",
    ok: res.ok,
    status: res.status,
    action: "issue",
    externalId: stringValue(body?.["id"]),
    externalUrl: stringValue(objectValue(body?.["links"])?.["html"] && objectValue(objectValue(body?.["links"])?.["html"])?.["href"]) || undefined,
    error: res.ok ? undefined : (stringValue(objectValue(body?.["error"])?.["message"]) || await safeText(res)),
  };
}

function slackPayload(notification: SecurityNotification): Record<string, unknown> {
  const fields = [
    markdownField("Project", notification.project),
    markdownField("Severity", notification.severity.toUpperCase()),
    markdownField("Findings", countText(notification)),
    markdownField("Scan", notification.scanMode || "scan"),
  ];
  return {
    text: `[${notification.severity.toUpperCase()}] ${notification.title}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*${escapeSlack(notification.title)}*\n${escapeSlack(notification.summary)}` } },
      { type: "section", fields },
      ...topFindingBlocks(notification),
      ...(notification.url ? [{ type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open scan" }, url: notification.url }] }] : []),
    ],
  };
}

function teamsPayload(notification: SecurityNotification): Record<string, unknown> {
  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: notification.title,
    themeColor: teamsColor(notification.severity),
    title: notification.title,
    text: notification.summary,
    sections: [
      {
        facts: [
          { name: "Project", value: notification.project },
          { name: "Severity", value: notification.severity.toUpperCase() },
          { name: "Findings", value: countText(notification) },
          { name: "Mode", value: notification.scanMode || "scan" },
        ],
        markdown: true,
      },
      ...(notification.findings?.length ? [{ title: "Top findings", text: markdownTopFindings(notification.findings.slice(0, 5)), markdown: true }] : []),
    ],
    potentialAction: notification.url ? [{ "@type": "OpenUri", name: "Open scan", targets: [{ os: "default", uri: notification.url }] }] : [],
  };
}

function markdownDescription(notification: SecurityNotification): string {
  const lines = [
    notification.summary,
    "",
    `Project: ${notification.project}`,
    `Severity: ${notification.severity.toUpperCase()}`,
    `Findings: ${countText(notification)}`,
  ];
  if (notification.target) lines.push(`Target: ${notification.target}`);
  if (notification.url) lines.push(`BreachScope scan: ${notification.url}`);
  if (notification.findings?.length) {
    lines.push("", "Top findings:");
    for (const finding of notification.findings.slice(0, 10)) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.title}${finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ""})` : ""}`);
      if (finding.remediation) lines.push(`  Fix: ${finding.remediation}`);
    }
  }
  return lines.join("\n");
}

function jiraDescription(notification: SecurityNotification): Record<string, unknown> {
  const paragraphs = markdownDescription(notification).split("\n").map((line) => ({
    type: "paragraph",
    content: line ? [{ type: "text", text: line }] : [],
  }));
  return { type: "doc", version: 1, content: paragraphs };
}

function markdownTopFindings(findings: SecurityFindingSummary[]): string {
  return findings.map((finding) => `* **${finding.severity.toUpperCase()}** ${finding.title}`).join("\n");
}

function topFindingBlocks(notification: SecurityNotification): Array<Record<string, unknown>> {
  const findings = notification.findings?.slice(0, 5) ?? [];
  if (findings.length === 0) return [];
  return [
    { type: "divider" },
    { type: "section", text: { type: "mrkdwn", text: `*Top findings*\n${findings.map((finding) => `• *${finding.severity.toUpperCase()}* ${escapeSlack(finding.title)}`).join("\n")}` } },
  ];
}

function markdownField(label: string, value: string): Record<string, string> {
  return { type: "mrkdwn", text: `*${label}*\n${value}` };
}

function countText(notification: SecurityNotification): string {
  const counts = notification.counts;
  if (!counts) return notification.findings?.length ? `${notification.findings.length}` : "0";
  const total = counts.total ?? Object.values(counts).reduce((sum, value) => sum + (typeof value === "number" ? value : 0), 0);
  return `${total} total (${counts.critical ?? 0} critical, ${counts.high ?? 0} high)`;
}

function pagerDutySeverity(severity: SecuritySeverity): "critical" | "error" | "warning" | "info" {
  if (severity === "critical") return "critical";
  if (severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "info";
}

function jiraPriority(severity: SecuritySeverity): string {
  if (severity === "critical" || severity === "high") return "High";
  if (severity === "medium") return "Medium";
  return "Low";
}

function linearPriority(severity: SecuritySeverity, configured?: number): number {
  if (configured && configured >= 0 && configured <= 4) return configured;
  if (severity === "critical") return 1;
  if (severity === "high") return 2;
  if (severity === "medium") return 3;
  return 4;
}

function bitbucketPriority(severity: SecuritySeverity): "trivial" | "minor" | "major" | "critical" | "blocker" {
  if (severity === "critical") return "blocker";
  if (severity === "high") return "critical";
  if (severity === "medium") return "major";
  if (severity === "low") return "minor";
  return "trivial";
}

function teamsColor(severity: SecuritySeverity): string {
  if (severity === "critical") return "D92D20";
  if (severity === "high") return "F04438";
  if (severity === "medium") return "F79009";
  if (severity === "low") return "0BA5EC";
  return "667085";
}

function mergeLabels(configured: string[], defaults: string[]): string[] {
  return [...new Set([...configured, ...defaults].map((label) => label.trim()).filter(Boolean))].slice(0, 20);
}

function stringConfig(config: Record<string, unknown> | null, key: string): string {
  const value = config?.[key];
  return typeof value === "string" ? value.trim() : "";
}

function arrayConfig(config: Record<string, unknown> | null, key: string): string[] {
  const value = config?.[key];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  if (typeof value === "string") return value.split(",").map((item) => item.trim()).filter(Boolean);
  return [];
}

function numberConfig(config: Record<string, unknown> | null, key: string): number | undefined {
  const value = config?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.join(", ");
  return "";
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function escapeSlack(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function safeJson(res: Response): Promise<Record<string, unknown> | null> {
  try {
    const body = await res.clone().json();
    return objectValue(body) ?? null;
  } catch {
    return null;
  }
}

async function safeText(res: Response): Promise<string> {
  await res.clone().text().catch(() => "");
  return `Provider returned HTTP ${res.status}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Outbound provider request was blocked";
}
