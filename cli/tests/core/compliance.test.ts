import { describe, expect, it } from "vitest";
import { mapCompliance } from "../../src/core/compliance.js";
import type { Finding } from "../../src/core/types.js";

describe("compliance mapping", () => {
  it("maps injection findings to OWASP and compliance controls", () => {
    const finding: Finding = {
      id: "sqli",
      title: "SQL injection",
      severity: "critical",
      category: "code",
      description: "Unsanitized input reaches a SQL query.",
    };

    const tags = mapCompliance(finding);

    expect(tags).toContain("OWASP-A03:2021 Injection");
    expect(tags).toContain("PCI-DSS-6.2 Custom Software Security");
  });
});
