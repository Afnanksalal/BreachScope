import { describe, expect, it } from "vitest";
import { applyDeterministicTriage, applyNoiseGate } from "../../src/core/noise-gate.js";
import type { Finding } from "../../src/core/types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding",
    title: "Finding",
    severity: "medium",
    category: "supply-chain",
    description: "Description",
    ...overrides,
  };
}

describe("noise gate", () => {
  it("shows direct high dependency vulnerabilities by default", () => {
    const result = applyDeterministicTriage(finding({
      id: "osv-direct-high",
      severity: "high",
      dependencyDepth: 0,
      signals: ["osv-version-match", "direct-dependency"],
    }));

    expect(result.triageDecision).toBe("show");
    expect(result.showByDefault).toBe(true);
  });

  it("moves transitive high vulnerabilities without exploit evidence to review", () => {
    const result = applyDeterministicTriage(finding({
      id: "osv-transitive-high",
      severity: "high",
      dependencyDepth: 3,
      signals: ["osv-version-match", "transitive-dependency"],
    }));

    expect(result.triageDecision).toBe("review");
    expect(result.showByDefault).toBe(false);
  });

  it("hides low-signal low severity CVEs by default but keeps them with --all-cves", async () => {
    const low = finding({
      id: "osv-low",
      severity: "low",
      signals: ["osv-version-match"],
    });

    const normal = await applyNoiseGate([low]);
    expect(normal.findings).toHaveLength(0);
    expect(normal.hiddenFindings).toHaveLength(1);

    const allCves = await applyNoiseGate([low], { allCves: true });
    expect(allCves.findings).toHaveLength(1);
    expect(allCves.findings[0]!.triageDecision).toBe("hide");
  });

  it("does not show missing low-impact hardening headers by default", () => {
    const result = applyDeterministicTriage(finding({
      id: "header-missing-x-frame-options",
      title: "Missing security header: x-frame-options",
      severity: "low",
      category: "blackbox",
      signals: ["browser-hardening-header"],
      evidenceStrength: "weak",
    }));

    expect(result.triageDecision).toBe("hide");
  });

  it("does not treat ordinary dependency hygiene findings as CVE noise", () => {
    const result = applyDeterministicTriage(finding({
      id: "lockfile-missing-integrity",
      title: "Package missing integrity hash",
      severity: "medium",
      category: "dependency",
      signals: [],
    }));

    expect(result.triageDecision).toBe("show");
  });

  it("shows confirmed sensitive probe evidence", () => {
    const result = applyDeterministicTriage(finding({
      id: "exposed-path--env",
      title: ".env file is accessible",
      severity: "critical",
      category: "blackbox",
      signals: ["confirmed-sensitive-exposure"],
      evidenceStrength: "confirmed",
    }));

    expect(result.triageDecision).toBe("show");
  });

  it("includes hidden probe findings only when --show-noise is enabled", async () => {
    const header = finding({
      id: "header-missing-x-content-type-options",
      severity: "low",
      category: "blackbox",
      signals: ["browser-hardening-header"],
    });

    const normal = await applyNoiseGate([header]);
    expect(normal.findings).toHaveLength(0);

    const noisy = await applyNoiseGate([header], { showNoise: true });
    expect(noisy.findings).toHaveLength(1);
  });
});
