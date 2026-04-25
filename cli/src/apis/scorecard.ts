import axios from "axios";
import { logger } from "../core/logger.js";
import type { ScorecardResult, ScorecardCheck, Finding } from "../core/types.js";

const BASE = "https://api.securityscorecards.dev";

/**
 * Fetch OpenSSF Scorecard for a GitHub repo.
 * @param githubSlug  "org/repo"
 */
export async function fetchScorecard(githubSlug: string): Promise<ScorecardResult | null> {
  try {
    const res = await axios.get(`${BASE}/projects/github.com/${githubSlug}`, {
      timeout: 12000,
      validateStatus: () => true,
      headers: { Accept: "application/json" },
    });

    if (res.status !== 200 || !res.data) return null;

    const raw = res.data as {
      score?: number;
      date?: string;
      repo?: { name: string };
      checks?: Array<{
        name: string;
        score: number;
        reason: string;
        documentation?: { url: string };
      }>;
    };

    return {
      score: raw.score ?? 0,
      date: raw.date ?? "",
      repo: raw.repo?.name ?? githubSlug,
      checks: (raw.checks ?? []).map((c) => ({
        name: c.name,
        score: c.score,
        reason: c.reason,
        documentation: c.documentation,
      })),
    };
  } catch (e) {
    logger.debug(`[scorecard] Failed for ${githubSlug}: ${e}`);
    return null;
  }
}

/**
 * Convert a ScorecardResult into actionable findings.
 */
export function scorecardToFindings(result: ScorecardResult, toolName: string): Finding[] {
  const findings: Finding[] = [];

  // Overall low score
  if (result.score < 4) {
    findings.push({
      id: `scorecard-overall-${toolName}`,
      title: `${toolName} has critically low OpenSSF Scorecard (${result.score}/10)`,
      severity: "critical",
      category: "supply-chain",
      tool: toolName,
      description: `${toolName}'s GitHub repository scores ${result.score}/10 on the OpenSSF Security Scorecard, indicating serious security hygiene gaps across maintenance, code review, vulnerability management, and CI security.`,
      remediation: "Consider replacing this dependency or accepting the risk. Monitor its advisories closely.",
      references: [`https://scorecard.dev/viewer/?uri=github.com/${result.repo}`],
    });
  } else if (result.score < 6) {
    findings.push({
      id: `scorecard-low-${toolName}`,
      title: `${toolName} has low OpenSSF Scorecard (${result.score}/10)`,
      severity: "high",
      category: "supply-chain",
      tool: toolName,
      description: `${toolName} scores ${result.score}/10, indicating notable security hygiene gaps.`,
      remediation: "Review the specific failing checks below and monitor for advisories.",
      references: [`https://scorecard.dev/viewer/?uri=github.com/${result.repo}`],
    });
  }

  // Check individual failing categories
  const CRITICAL_CHECKS: Record<string, { threshold: number; severity: Finding["severity"]; remediation: string }> = {
    "Vulnerabilities": {
      threshold: 7,
      severity: "critical",
      remediation: "Unpatched CVEs exist in this package. Run `npm audit` and check OSV.dev.",
    },
    "Binary-Artifacts": {
      threshold: 5,
      severity: "high",
      remediation: "The repo contains binary artifacts that cannot be audited. Treat with extreme caution.",
    },
    "Pinned-Dependencies": {
      threshold: 5,
      severity: "high",
      remediation: "CI/CD dependencies are not pinned — supply chain attacks can inject malicious code.",
    },
    "Token-Permissions": {
      threshold: 5,
      severity: "high",
      remediation: "GitHub Actions tokens have excessive permissions — a compromised workflow could push malicious code.",
    },
    "Branch-Protection": {
      threshold: 3,
      severity: "high",
      remediation: "Main branch is unprotected — maintainer accounts can be used to directly push malicious code.",
    },
    "Maintained": {
      threshold: 3,
      severity: "medium",
      remediation: "This project appears unmaintained. Security vulnerabilities may go unpatched indefinitely.",
    },
    "Code-Review": {
      threshold: 5,
      severity: "medium",
      remediation: "Code is merged without review — a single compromised maintainer could ship malicious code.",
    },
    "SAST": {
      threshold: 3,
      severity: "low",
      remediation: "No static analysis is run on this codebase. Vulnerability-class bugs may go undetected.",
    },
  };

  for (const check of result.checks) {
    const rule = CRITICAL_CHECKS[check.name];
    if (rule && check.score < rule.threshold && check.score >= 0) {
      findings.push({
        id: `scorecard-${check.name.toLowerCase().replace(/[^a-z]/g, "-")}-${toolName}`,
        title: `${toolName}: Scorecard check "${check.name}" failed (${check.score}/10)`,
        severity: rule.severity,
        category: "supply-chain",
        tool: toolName,
        description: check.reason,
        remediation: rule.remediation,
        references: check.documentation?.url ? [check.documentation.url] : undefined,
      });
    }
  }

  return findings;
}
