import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../../src/core/policy.js";
import type { Finding } from "../../src/core/types.js";

const highFinding: Finding = {
  id: "pkg-vuln",
  title: "Known vulnerable package lodash",
  severity: "high",
  category: "dependency",
  description: "Package is vulnerable.",
  tool: "lodash",
};

describe("policy evaluation", () => {
  it("creates a policy violation when severity threshold is exceeded", () => {
    const result = evaluatePolicy([highFinding], { failOn: "high" });

    expect(result.violations.some((finding) => finding.id === "policy-severity-threshold")).toBe(true);
  });

  it("suppresses findings with active approved exceptions", () => {
    const stamped = evaluatePolicy([highFinding]).findings[0]!;
    const result = evaluatePolicy([stamped], {
      suppressions: [{
        fingerprint: stamped.fingerprint!,
        reason: "Accepted for a migration window",
        expiresAt: "2999-01-01T00:00:00Z",
      }],
    });

    expect(result.findings).toHaveLength(0);
    expect(result.suppressed).toHaveLength(1);
  });

  it("detects blocked packages", () => {
    const result = evaluatePolicy([highFinding], { blockedPackages: ["lodash"] });

    expect(result.violations.some((finding) => finding.id.startsWith("policy-blocked-package"))).toBe(true);
  });
});
