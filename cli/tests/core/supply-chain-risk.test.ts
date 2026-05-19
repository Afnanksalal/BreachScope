import { describe, expect, it } from "vitest";
import { scoreSupplyChainRisk } from "../../src/core/supply-chain-risk.js";

describe("scoreSupplyChainRisk", () => {
  it("scores clean metadata as zero risk", () => {
    const result = scoreSupplyChainRisk({
      osvCount: 0,
      scorecardScore: 9,
      depsDevScore: 9,
      maintainerCount: 5,
      weeklyDownloads: 500,
      publishedAt: "2020-01-01T00:00:00.000Z",
      sourceFindings: 0,
    });

    expect(result.score).toBe(0);
    expect(result.reasons).toHaveLength(0);
  });

  it("combines vulnerability, maintainer, and source-code risk signals", () => {
    const result = scoreSupplyChainRisk({
      osvCount: 2,
      scorecardScore: 3.2,
      depsDevScore: 3.5,
      maintainerCount: 1,
      weeklyDownloads: 2_000_000,
      sourceFindings: 2,
      deprecated: true,
      license: "UNLICENSED",
    });

    expect(result.score).toBe(100);
    expect(result.reasons.some((reason) => reason.includes("known vulnerability"))).toBe(true);
    expect(result.reasons.some((reason) => reason.includes("single maintainer"))).toBe(true);
    expect(result.reasons.some((reason) => reason.includes("deprecated"))).toBe(true);
  });
});
