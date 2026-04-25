import axios from "axios";
import { logger } from "../core/logger.js";
import type { ScorecardResult, ScorecardCheck, Finding } from "../core/types.js";

// Migrating to api.scorecard.dev — securityscorecards.dev will redirect for 12 months
const BASE = "https://api.scorecard.dev";

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
 * @param osvVulnCount  Number of CVEs OSV found for the *installed version*.
 *                      When 0, the "Vulnerabilities" scorecard check is downgraded —
 *                      because scorecard counts repo-level history, not version-specific CVEs.
 */
export function scorecardToFindings(
  result: ScorecardResult,
  toolName: string,
  opts?: { osvVulnCount?: number }
): Finding[] {
  const findings: Finding[] = [];
  const osvVulnCount = opts?.osvVulnCount ?? -1; // -1 = unknown

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

  // Security checks — directly impact safety of using this package
  const SECURITY_CHECKS: Record<string, { threshold: number; severity: Finding["severity"]; remediation: string }> = {
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
    "Branch-Protection": {
      threshold: 3,
      severity: "high",
      remediation: "Main branch is unprotected — maintainer accounts could push malicious code directly.",
    },
    "Maintained": {
      threshold: 3,
      severity: "medium",
      remediation: "This project appears unmaintained. Security vulnerabilities may go unpatched indefinitely.",
    },
  };

  // Maintainer practice checks — describe the package dev team's CI/CD hygiene,
  // NOT vulnerabilities in the package itself. Much lower signal for end users.
  const PRACTICE_CHECKS: Record<string, { threshold: number; severity: Finding["severity"]; remediation: string }> = {
    "Pinned-Dependencies": {
      threshold: 5,
      severity: "low",
      remediation: "The package's own CI/CD dependencies are not pinned — a compromised build tool could affect future releases.",
    },
    "Token-Permissions": {
      threshold: 5,
      severity: "low",
      remediation: "The package's GitHub Actions use overly broad token permissions. This is a risk to maintainers, not to your app directly.",
    },
    "Code-Review": {
      threshold: 5,
      severity: "low",
      remediation: "Code may be merged without review — a single compromised maintainer could ship malicious code in future releases.",
    },
    "SAST": {
      threshold: 3,
      severity: "info",
      remediation: "The package maintainers do not run static analysis. This is a maintainer practice gap, not a known vulnerability.",
    },
  };

  for (const check of result.checks) {
    const securityRule = SECURITY_CHECKS[check.name];
    const practiceRule = PRACTICE_CHECKS[check.name];
    const rule = securityRule ?? practiceRule;
    if (!rule || check.score >= rule.threshold || check.score < 0) continue;

    // "Vulnerabilities" scorecard check counts every CVE ever filed against the repo —
    // it is NOT version-specific. When OSV already confirmed 0 CVEs for the installed
    // version, the scorecard number is noise. Downgrade and explain instead of alarming.
    if (check.name === "Vulnerabilities") {
      if (osvVulnCount === 0) {
        findings.push({
          id: `scorecard-vulnerabilities-${toolName}`,
          title: `${toolName}: Repository has historical CVEs (none affect your installed version)`,
          severity: "info",
          category: "supply-chain",
          tool: toolName,
          description: `OpenSSF Scorecard reports unresolved CVEs at the repository level (${check.reason}). OSV.dev found no vulnerabilities for your installed version of ${toolName} — the scorecard count reflects the repo's full history, not your specific version.`,
          remediation: "No action required for the installed version. Recheck on upgrades.",
          references: check.documentation?.url ? [check.documentation.url] : undefined,
        });
      } else {
        findings.push({
          id: `scorecard-vulnerabilities-${toolName}`,
          title: `${toolName}: Scorecard "Vulnerabilities" check failed (${check.score}/10)`,
          severity: rule.severity,
          category: "supply-chain",
          tool: toolName,
          description: `${check.reason}. OSV.dev confirmed ${osvVulnCount > 0 ? osvVulnCount : "additional"} vulnerabilities in this package — upgrade or replace.`,
          remediation: rule.remediation,
          references: check.documentation?.url ? [check.documentation.url] : undefined,
        });
      }
      continue;
    }

    const isMaintainerPractice = !!practiceRule;
    const titlePrefix = isMaintainerPractice
      ? `${toolName}: [Maintainer Practice] `
      : `${toolName}: `;

    findings.push({
      id: `scorecard-${check.name.toLowerCase().replace(/[^a-z]/g, "-")}-${toolName}`,
      title: `${titlePrefix}${check.name} check failed (${check.score}/10)`,
      severity: rule.severity,
      category: "supply-chain",
      tool: toolName,
      description: isMaintainerPractice
        ? `${check.reason} — Note: this describes the package maintainer's CI/CD practices, not a vulnerability in the package code itself.`
        : check.reason,
      remediation: rule.remediation,
      references: check.documentation?.url ? [check.documentation.url] : undefined,
    });
  }

  return findings;
}
