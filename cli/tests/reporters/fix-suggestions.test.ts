import { describe, expect, it } from "vitest";
import { renderFixSuggestions } from "../../src/reporters/fix-suggestions.js";
import type { ScanResult } from "../../src/core/types.js";

describe("renderFixSuggestions", () => {
  it("prioritizes findings and emits concrete remediation guidance", () => {
    const result: ScanResult = {
      target: "app",
      startedAt: new Date(),
      completedAt: new Date(),
      metadata: {},
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      findings: [{
        id: "sql-injection",
        title: "SQL injection",
        severity: "critical",
        category: "code",
        description: "String-built SQL accepts user input.",
      }],
    };

    const markdown = renderFixSuggestions(result);

    expect(markdown).toContain("CRITICAL - SQL injection");
    expect(markdown).toContain("parameterized queries");
  });
});
