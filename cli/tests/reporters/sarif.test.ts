import { describe, expect, it } from "vitest";
import { renderSarifReport } from "../../src/reporters/sarif.js";
import type { ScanResult } from "../../src/core/types.js";

describe("renderSarifReport", () => {
  it("renders SARIF 2.1.0 with rules, results, locations, and fingerprints", () => {
    const result: ScanResult = {
      target: "/repo",
      startedAt: new Date("2026-01-01T00:00:00Z"),
      completedAt: new Date("2026-01-01T00:00:01Z"),
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      metadata: {},
      findings: [{
        id: "hardcoded-secret",
        title: "Hardcoded secret",
        severity: "high",
        category: "code",
        description: "A secret was committed.",
        file: "/repo/src/app.ts",
        line: 12,
      }],
    };

    const sarif = JSON.parse(renderSarifReport(result)) as {
      version: string;
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: Array<{ ruleId: string; locations: unknown[]; fingerprints: Record<string, string> }> }>;
    };

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe("hardcoded-secret");
    expect(sarif.runs[0]?.results[0]?.locations).toHaveLength(1);
    expect(sarif.runs[0]?.results[0]?.fingerprints.breachscope).toMatch(/^[a-f0-9]{64}$/);
  });
});
