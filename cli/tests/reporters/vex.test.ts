import { describe, expect, it } from "vitest";
import { renderVexReport } from "../../src/reporters/vex.js";
import type { ScanResult } from "../../src/core/types.js";

describe("renderVexReport", () => {
  it("renders OpenVEX statements for vulnerability findings", () => {
    const result: ScanResult = {
      target: "pkg:npm/example@1.0.0",
      startedAt: new Date("2026-01-01T00:00:00Z"),
      completedAt: new Date("2026-01-01T00:00:01Z"),
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      metadata: {},
      findings: [{
        id: "osv-GHSA-abcd-efgh-ijkl-example",
        title: "example: GHSA-abcd-efgh-ijkl vulnerable package",
        severity: "high",
        category: "supply-chain",
        description: "Known vulnerability.",
        vexStatus: "affected",
      }],
    };

    const vex = JSON.parse(renderVexReport(result)) as {
      "@context": string;
      statements: Array<{ vulnerability: { name: string }; status: string }>;
    };

    expect(vex["@context"]).toContain("openvex");
    expect(vex.statements).toHaveLength(1);
    expect(vex.statements[0]?.status).toBe("affected");
  });
});
