export interface SecurityNotification {
  project: string;
  scanId?: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  summary: string;
  url?: string;
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
  error?: string;
}

export async function dispatchSecurityNotification(
  integration: IntegrationConfig,
  notification: SecurityNotification
): Promise<IntegrationResult> {
  const provider = integration.provider.toLowerCase();
  if (provider === "slack") return postWebhook(provider, integration, slackPayload(notification));
  if (provider === "teams") return postWebhook(provider, integration, teamsPayload(notification));
  if (provider === "pagerduty") return postPagerDuty(integration, notification);
  if (provider === "jira") return postJira(integration, notification);
  if (provider === "linear") return postLinear(integration, notification);
  if (provider === "github") return postGitHubIssue(integration, notification);
  if (["gitlab", "bitbucket", "saml", "scim"].includes(provider)) {
    return { provider, ok: true, status: 204 };
  }
  return { provider, ok: false, status: 400, error: "Unsupported integration provider" };
}

async function postWebhook(
  provider: string,
  integration: IntegrationConfig,
  payload: Record<string, unknown>
): Promise<IntegrationResult> {
  const webhookUrl = integration.secret || stringConfig(integration.config, "webhookUrl");
  if (!webhookUrl) return { provider, ok: false, status: 400, error: "Missing webhookUrl" };
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return { provider, ok: res.ok, status: res.status, error: res.ok ? undefined : await safeText(res) };
}

async function postPagerDuty(
  integration: IntegrationConfig,
  notification: SecurityNotification
): Promise<IntegrationResult> {
  const routingKey = integration.secret || stringConfig(integration.config, "routingKey");
  if (!routingKey) return { provider: "pagerduty", ok: false, status: 400, error: "Missing routingKey" };
  const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      routing_key: routingKey,
      event_action: "trigger",
      payload: {
        summary: notification.title,
        source: notification.project,
        severity: pagerDutySeverity(notification.severity),
        custom_details: notification,
      },
      links: notification.url ? [{ href: notification.url, text: "BreachScope scan" }] : [],
    }),
  });
  return { provider: "pagerduty", ok: res.ok, status: res.status, error: res.ok ? undefined : await safeText(res) };
}

async function postJira(
  integration: IntegrationConfig,
  notification: SecurityNotification
): Promise<IntegrationResult> {
  const siteUrl = stringConfig(integration.config, "siteUrl");
  const email = stringConfig(integration.config, "email");
  const apiToken = integration.secret || stringConfig(integration.config, "apiToken");
  const projectKey = stringConfig(integration.config, "projectKey");
  if (!siteUrl || !email || !apiToken || !projectKey) {
    return { provider: "jira", ok: false, status: 400, error: "Missing Jira siteUrl, email, apiToken, or projectKey" };
  }
  const res = await fetch(`${siteUrl.replace(/\/$/, "")}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fields: {
        project: { key: projectKey },
        summary: notification.title,
        description: {
          type: "doc",
          version: 1,
          content: [{ type: "paragraph", content: [{ type: "text", text: notification.summary }] }],
        },
        issuetype: { name: "Bug" },
      },
    }),
  });
  return { provider: "jira", ok: res.ok, status: res.status, error: res.ok ? undefined : await safeText(res) };
}

async function postLinear(
  integration: IntegrationConfig,
  notification: SecurityNotification
): Promise<IntegrationResult> {
  const apiKey = integration.secret || stringConfig(integration.config, "apiKey");
  const teamId = stringConfig(integration.config, "teamId");
  if (!apiKey || !teamId) return { provider: "linear", ok: false, status: 400, error: "Missing Linear apiKey or teamId" };
  const res = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: {
      Authorization: apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id } } }",
      variables: {
        input: {
          teamId,
          title: notification.title,
          description: `${notification.summary}${notification.url ? `\n\n${notification.url}` : ""}`,
        },
      },
    }),
  });
  return { provider: "linear", ok: res.ok, status: res.status, error: res.ok ? undefined : await safeText(res) };
}

async function postGitHubIssue(
  integration: IntegrationConfig,
  notification: SecurityNotification
): Promise<IntegrationResult> {
  const repoFullName = stringConfig(integration.config, "repoFullName");
  const token = integration.secret || stringConfig(integration.config, "token");
  const createIssues = integration.config?.["createIssues"] === true;

  if (!repoFullName || !token) {
    return { provider: "github", ok: false, status: 400, error: "Missing GitHub repoFullName or token" };
  }
  if (!createIssues) {
    return { provider: "github", ok: true, status: 204 };
  }

  const res = await fetch(`https://api.github.com/repos/${repoFullName}/issues`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2026-03-10",
    },
    body: JSON.stringify({
      title: notification.title.slice(0, 240),
      body: `${notification.summary}${notification.url ? `\n\n${notification.url}` : ""}`,
      labels: ["security", "breachscope"],
    }),
  });

  return { provider: "github", ok: res.ok, status: res.status, error: res.ok ? undefined : await safeText(res) };
}

function slackPayload(notification: SecurityNotification): Record<string, unknown> {
  return {
    text: `[${notification.severity.toUpperCase()}] ${notification.title}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*${notification.title}*\n${notification.summary}` } },
      { type: "context", elements: [{ type: "mrkdwn", text: `Project: ${notification.project}` }] },
    ],
  };
}

function teamsPayload(notification: SecurityNotification): Record<string, unknown> {
  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: notification.title,
    themeColor: notification.severity === "critical" || notification.severity === "high" ? "D92D20" : "F79009",
    title: notification.title,
    text: notification.summary,
    potentialAction: notification.url ? [{ "@type": "OpenUri", name: "Open scan", targets: [{ os: "default", uri: notification.url }] }] : [],
  };
}

function pagerDutySeverity(severity: SecurityNotification["severity"]): "critical" | "error" | "warning" | "info" {
  if (severity === "critical") return "critical";
  if (severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "info";
}

function stringConfig(config: Record<string, unknown> | null, key: string): string {
  const value = config?.[key];
  return typeof value === "string" ? value : "";
}

async function safeText(res: Response): Promise<string> {
  return (await res.text().catch(() => "")).slice(0, 500);
}
