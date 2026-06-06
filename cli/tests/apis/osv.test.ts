import { describe, expect, it } from "vitest";
import { osvToFindings } from "../../src/apis/osv.js";
import type { OsvVulnerability } from "../../src/core/types.js";

function vuln(overrides: Partial<OsvVulnerability>): OsvVulnerability {
  return {
    id: "GHSA-test-0000",
    summary: "Test advisory",
    aliases: [],
    severity: [{ type: "CVSS_V3", score: "7.5" }],
    affected: [{
      package: { name: "demo", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
    }],
    references: [{ type: "WEB", url: "https://example.com/advisory" }],
    modified: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("osvToFindings", () => {
  it("groups advisories by package and fix path", () => {
    const findings = osvToFindings([
      vuln({ id: "GHSA-one", aliases: ["CVE-2026-10001"], summary: "First issue" }),
      vuln({ id: "GHSA-two", aliases: ["CVE-2026-10002"], summary: "Second issue" }),
    ], "demo", { packageVersion: "1.0.0", dependencyDepth: 0, dependencyScope: "production" });

    expect(findings).toHaveLength(1);
    expect(findings[0]!.relatedVulnerabilities).toHaveLength(2);
    expect(findings[0]!.detail).toContain("CVE-2026-10001");
    expect(findings[0]!.detail).toContain("CVE-2026-10002");
    expect(findings[0]!.fixedVersion).toBe("1.2.3");
    expect(findings[0]!.signals).toContain("grouped-advisories");
  });

  it("keeps separate findings when fix paths differ", () => {
    const findings = osvToFindings([
      vuln({ id: "GHSA-one", affected: [{ package: { name: "demo", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] }] }),
      vuln({ id: "GHSA-two", affected: [{ package: { name: "demo", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }] }),
    ], "demo");

    expect(findings).toHaveLength(2);
  });
});
