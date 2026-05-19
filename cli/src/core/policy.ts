import fs from "fs";
import yaml from "js-yaml";
import { attachFingerprints, fingerprintFinding } from "./baseline.js";
import type { Finding, PolicyConfig, Severity } from "./types.js";

export interface PolicyEvaluation {
  findings: Finding[];
  violations: Finding[];
  suppressed: Finding[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function loadPolicy(path: string): PolicyConfig {
  const raw = fs.readFileSync(path, "utf-8");
  const parsed = path.endsWith(".json") ? JSON.parse(raw) : yaml.load(raw);
  const policy = isPolicyDocument(parsed) ? parsed.policy : parsed;
  return (policy ?? {}) as PolicyConfig;
}

export function evaluatePolicy(findings: Finding[], policy: PolicyConfig = {}): PolicyEvaluation {
  const stamped = attachFingerprints(findings);
  const suppressed = collectActiveSuppressions(stamped, policy);
  const suppressedIds = new Set(suppressed.map((finding) => finding.fingerprint));
  const activeFindings = stamped.filter((finding) => !suppressedIds.has(finding.fingerprint));

  const violations: Finding[] = [
    ...evaluateSeverityThreshold(activeFindings, policy.failOn),
    ...evaluateFindingBudgets(activeFindings, policy.maxFindings),
    ...evaluateBlockedPackages(activeFindings, policy.blockedPackages),
    ...evaluateDeniedCategories(activeFindings, policy.deniedCategories),
  ];

  return {
    findings: activeFindings,
    violations: attachFingerprints(violations),
    suppressed,
  };
}

export function meetsSeverityThreshold(finding: Finding, failOn: Severity): boolean {
  return SEVERITY_ORDER[finding.severity] <= SEVERITY_ORDER[failOn];
}

function evaluateSeverityThreshold(findings: Finding[], failOn?: Severity): Finding[] {
  if (!failOn) return [];
  const failures = findings.filter((finding) => meetsSeverityThreshold(finding, failOn));
  if (failures.length === 0) return [];
  return [{
    id: "policy-severity-threshold",
    title: `Policy threshold exceeded: ${failures.length} finding(s) at or above ${failOn}`,
    severity: "high",
    category: "policy",
    description: "The scan contains findings that violate the configured policy severity threshold.",
    remediation: "Fix the findings, lower their verified severity, or add an expiring policy suppression with approval.",
    detail: failures.slice(0, 10).map((finding) => `${finding.severity}: ${finding.title}`).join("\n"),
    tool: "breachscope-policy",
  }];
}

function evaluateFindingBudgets(
  findings: Finding[],
  budgets: PolicyConfig["maxFindings"] = {}
): Finding[] {
  const violations: Finding[] = [];
  for (const [severity, max] of Object.entries(budgets) as Array<[Severity, number]>) {
    const count = findings.filter((finding) => finding.severity === severity).length;
    if (typeof max === "number" && count > max) {
      violations.push({
        id: `policy-max-${severity}`,
        title: `Policy budget exceeded for ${severity} findings`,
        severity: severity === "critical" || severity === "high" ? severity : "medium",
        category: "policy",
        description: `The policy allows at most ${max} ${severity} finding(s), but the scan produced ${count}.`,
        remediation: "Fix findings or document an expiring suppression for accepted risk.",
        tool: "breachscope-policy",
      });
    }
  }
  return violations;
}

function evaluateBlockedPackages(findings: Finding[], blockedPackages: string[] = []): Finding[] {
  if (blockedPackages.length === 0) return [];
  const blocked = new Set(blockedPackages.map((pkg) => pkg.toLowerCase()));
  return findings
    .filter((finding) => {
      const target = `${finding.tool ?? ""} ${finding.title} ${finding.detail ?? ""}`.toLowerCase();
      return [...blocked].some((pkg) => target.includes(pkg));
    })
    .map((finding) => ({
      id: `policy-blocked-package-${fingerprintFinding(finding).slice(0, 12)}`,
      title: `Blocked package policy matched: ${finding.title}`,
      severity: "high",
      category: "policy",
      description: "A finding references a package blocked by policy.",
      remediation: "Remove or replace the blocked package, or document a time-bound exception.",
      detail: finding.detail,
      tool: "breachscope-policy",
      file: finding.file,
      line: finding.line,
    }));
}

function evaluateDeniedCategories(
  findings: Finding[],
  deniedCategories: PolicyConfig["deniedCategories"] = []
): Finding[] {
  if (deniedCategories.length === 0) return [];
  const denied = new Set(deniedCategories);
  const matches = findings.filter((finding) => denied.has(finding.category));
  if (matches.length === 0) return [];
  return [{
    id: "policy-denied-category",
    title: `Denied finding categories present: ${[...denied].join(", ")}`,
    severity: "high",
    category: "policy",
    description: `${matches.length} finding(s) use a category blocked by policy.`,
    remediation: "Resolve those findings or remove the category from deniedCategories.",
    detail: matches.slice(0, 10).map((finding) => `${finding.category}: ${finding.title}`).join("\n"),
    tool: "breachscope-policy",
  }];
}

function collectActiveSuppressions(findings: Finding[], policy: PolicyConfig): Finding[] {
  const suppressions = policy.suppressions ?? [];
  const now = Date.now();
  const active = new Map(
    suppressions
      .filter((suppression) => Date.parse(suppression.expiresAt) > now)
      .map((suppression) => [suppression.fingerprint, suppression])
  );

  return findings
    .filter((finding) => active.has(finding.fingerprint!))
    .map((finding) => ({
      ...finding,
      status: "accepted-risk",
      suppressedUntil: active.get(finding.fingerprint!)?.expiresAt,
    }));
}

function isPolicyDocument(value: unknown): value is { policy: PolicyConfig } {
  return typeof value === "object" && value !== null && "policy" in value;
}
