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
});
