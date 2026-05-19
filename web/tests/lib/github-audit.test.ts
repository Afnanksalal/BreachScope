import { describe, expect, it } from "vitest";
import { parseGitHubRepo, buildGitHubAuditMarkdown } from "@/lib/github-audit";

describe("parseGitHubRepo", () => {
  it("accepts owner/repo slugs", () => {
    expect(parseGitHubRepo("acme/app")).toBe("acme/app");
  });

  it("accepts HTTPS repository URLs", () => {
    expect(parseGitHubRepo("https://github.com/acme/app.git")).toBe("acme/app");
  });

  it("accepts SSH repository URLs", () => {
    expect(parseGitHubRepo("git@github.com:acme/app.git")).toBe("acme/app");
  });

  it("rejects malformed repository values", () => {
    expect(parseGitHubRepo("https://example.com/acme/app")).toBeNull();
  });
});

describe("buildGitHubAuditMarkdown", () => {
  it("renders a compact audit summary", () => {
    const markdown = buildGitHubAuditMarkdown({
      repoFullName: "acme/app",
      repositoryUrl: "https://github.com/acme/app",
      defaultBranch: "main",
      visibility: "private",
      openPullRequests: [],
      steps: [],
      findings: [{
        title: "Default branch has no protection",
        severity: "high",
        category: "toolchain",
        description: "Branch protection is missing.",
        remediation: "Enable branch protection.",
      }],
    }, "https://breachscope.test/dashboard/scan/1");

    expect(markdown).toContain("BreachScope GitHub audit");
    expect(markdown).toContain("acme/app");
    expect(markdown).toContain("1 high");
    expect(markdown).toContain("Enable branch protection");
  });
});
