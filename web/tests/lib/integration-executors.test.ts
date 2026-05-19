import { beforeEach, describe, expect, it, vi } from "vitest";
import { dispatchSecurityNotification } from "@/lib/integration-executors";

describe("dispatchSecurityNotification", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("posts Slack webhook payloads", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "slack",
      name: "Slack",
      config: { webhookUrl: "https://hooks.slack.test" },
    }, {
      project: "app",
      title: "Critical finding",
      severity: "critical",
      summary: "A critical issue was found.",
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith("https://hooks.slack.test", expect.objectContaining({ method: "POST" }));
  });

  it("rejects missing provider configuration", async () => {
    const result = await dispatchSecurityNotification({
      provider: "pagerduty",
      name: "PagerDuty",
      config: {},
    }, {
      project: "app",
      title: "High finding",
      severity: "high",
      summary: "A high issue was found.",
    });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
  });

  it("creates GitHub issues when issue routing is enabled", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ html_url: "https://github.test/issue/1" }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "github",
      name: "GitHub",
      config: { repoFullName: "acme/app", createIssues: true },
      secret: "ghp_test",
    }, {
      project: "app",
      title: "Critical finding",
      severity: "critical",
      summary: "A critical issue was found.",
      url: "https://breachscope.test/dashboard/scan/1",
    });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(201);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/app/issues",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("creates Jira issues with labels and priority", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ key: "SEC-12" }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "jira",
      name: "Jira",
      config: { siteUrl: "https://acme.atlassian.net", email: "sec@acme.test", projectKey: "SEC", issueType: "Task", labels: ["security"] },
      secret: "jira-token",
    }, {
      project: "app",
      title: "High finding",
      severity: "high",
      summary: "A high issue was found.",
      counts: { total: 1, high: 1 },
    });

    expect(result.ok).toBe(true);
    expect(result.externalUrl).toBe("https://acme.atlassian.net/browse/SEC-12");
    expect(fetchMock).toHaveBeenCalledWith("https://acme.atlassian.net/rest/api/3/issue", expect.objectContaining({ method: "POST" }));
  });

  it("creates Linear issues with configured metadata", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: { issueCreate: { success: true, issue: { id: "lin-id", identifier: "SEC-1", url: "https://linear.test/SEC-1" } } },
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "linear",
      name: "Linear",
      config: { teamId: "team-id", labelIds: ["label-id"], priority: 2 },
      secret: "lin_api_key",
    }, {
      project: "app",
      title: "High finding",
      severity: "high",
      summary: "A high issue was found.",
    });

    expect(result.ok).toBe(true);
    expect(result.externalUrl).toBe("https://linear.test/SEC-1");
  });

  it("creates GitLab issues", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ iid: 9, web_url: "https://gitlab.test/acme/app/-/issues/9" }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "gitlab",
      name: "GitLab",
      config: { instanceUrl: "https://gitlab.test", projectPath: "acme/app", createIssues: true },
      secret: "glpat",
    }, {
      project: "app",
      title: "Critical finding",
      severity: "critical",
      summary: "A critical issue was found.",
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith("https://gitlab.test/api/v4/projects/acme%2Fapp/issues", expect.objectContaining({ method: "POST" }));
  });

  it("creates Bitbucket issues", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 7,
      links: { html: { href: "https://bitbucket.org/acme/app/issues/7" } },
    }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dispatchSecurityNotification({
      provider: "bitbucket",
      name: "Bitbucket",
      config: { workspace: "acme", repoSlug: "app", username: "sec" },
      secret: "app-password",
    }, {
      project: "app",
      title: "Critical finding",
      severity: "critical",
      summary: "A critical issue was found.",
    });

    expect(result.ok).toBe(true);
    expect(result.externalUrl).toBe("https://bitbucket.org/acme/app/issues/7");
  });
});
