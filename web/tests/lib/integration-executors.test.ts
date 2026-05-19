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
});
