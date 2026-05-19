export interface SupplyChainRiskInput {
  osvCount?: number;
  criticalFindings?: number;
  highFindings?: number;
  scorecardScore?: number;
  depsDevScore?: number;
  maintainerCount?: number;
  weeklyDownloads?: number;
  publishedAt?: string;
  sourceFindings?: number;
  deprecated?: boolean;
  license?: string;
}

export interface SupplyChainRiskScore {
  score: number;
  summary: string;
  reasons: string[];
}

const RISKY_LICENSES = new Set(["unlicensed", "unknown", "noassertion"]);

export function scoreSupplyChainRisk(input: SupplyChainRiskInput): SupplyChainRiskScore {
  const reasons: string[] = [];
  let score = 0;

  const osvCount = input.osvCount ?? 0;
  if (osvCount > 0) {
    const delta = Math.min(70, osvCount * 25);
    score += delta;
    reasons.push(`${osvCount} known vulnerability record(s) matched the installed package/version`);
  }

  if ((input.criticalFindings ?? 0) > 0) {
    score += Math.min(40, (input.criticalFindings ?? 0) * 20);
    reasons.push(`${input.criticalFindings} critical supply-chain finding(s)`);
  }

  if ((input.highFindings ?? 0) > 0) {
    score += Math.min(30, (input.highFindings ?? 0) * 10);
    reasons.push(`${input.highFindings} high-severity supply-chain finding(s)`);
  }

  if (typeof input.scorecardScore === "number") {
    if (input.scorecardScore < 4) {
      score += 30;
      reasons.push(`OpenSSF Scorecard is critically low (${input.scorecardScore}/10)`);
    } else if (input.scorecardScore < 6) {
      score += 15;
      reasons.push(`OpenSSF Scorecard is low (${input.scorecardScore}/10)`);
    }
  }

  if (typeof input.depsDevScore === "number" && input.depsDevScore < 4) {
    score += 20;
    reasons.push(`deps.dev security score is low (${input.depsDevScore}/10)`);
  }

  const downloads = input.weeklyDownloads ?? 0;
  if (input.maintainerCount === 0) {
    score += 25;
    reasons.push("registry metadata reports no maintainers");
  } else if (input.maintainerCount === 1) {
    const delta = downloads > 100_000 ? 20 : 8;
    score += delta;
    reasons.push("package has a single maintainer");
  }

  if (downloads > 1_000_000) {
    score += 10;
    reasons.push("package has million-plus weekly download blast radius");
  } else if (downloads > 100_000) {
    score += 5;
    reasons.push("package has high weekly download blast radius");
  }

  const daysSincePublish = input.publishedAt
    ? (Date.now() - new Date(input.publishedAt).getTime()) / 86_400_000
    : Number.POSITIVE_INFINITY;
  if (Number.isFinite(daysSincePublish) && daysSincePublish >= 0 && daysSincePublish < 30) {
    score += 10;
    reasons.push(`latest release is very recent (${Math.floor(daysSincePublish)} day(s) old)`);
  }

  if ((input.sourceFindings ?? 0) > 0) {
    score += Math.min(45, (input.sourceFindings ?? 0) * 15);
    reasons.push(`${input.sourceFindings} suspicious source or lifecycle-script pattern(s)`);
  }

  if (input.deprecated) {
    score += 15;
    reasons.push("registry marks this package as deprecated");
  }

  const license = normalizeLicense(input.license);
  if (license && RISKY_LICENSES.has(license)) {
    score += 8;
    reasons.push(`package license is ${input.license}`);
  }

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));
  const summary = reasons.length > 0
    ? `Deterministic risk score ${finalScore}/100 based on ${reasons.slice(0, 3).join("; ")}.`
    : "Deterministic risk score 0/100; no material supply-chain risk signals were present in available metadata.";

  return {
    score: finalScore,
    summary,
    reasons,
  };
}

function normalizeLicense(license?: string): string {
  return (license ?? "").trim().toLowerCase();
}
