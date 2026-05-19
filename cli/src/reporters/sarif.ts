import fs from "fs";
import path from "path";
import { attachFingerprints } from "../core/baseline.js";
import type { Finding, ScanResult } from "../core/types.js";

interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      semanticVersion?: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help?: { text: string; markdown: string };
  properties: {
    category: string;
    precision: "low" | "medium" | "high" | "very-high";
    "security-severity": string;
    tags: string[];
  };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  fingerprints: Record<string, string>;
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  properties: {
    severity: Finding["severity"];
    category: Finding["category"];
    tool?: string;
    references?: string[];
  };
}

const SECURITY_SEVERITY: Record<Finding["severity"], string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "2.0",
  info: "0.0",
};

export function renderSarifReport(
  result: ScanResult,
  outputFile?: string,
  version?: string
): string {
  const findings = attachFingerprints(result.findings);
  const rules = buildRules(findings);
  const log: SarifLog = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "BreachScope",
          informationUri: "https://github.com/Afnanksalal/BreachScope",
          semanticVersion: version,
          rules,
        },
      },
      results: findings.map((finding) => toSarifResult(finding, result.target)),
    }],
  };

  const json = JSON.stringify(log, null, 2);
  if (outputFile) {
    fs.writeFileSync(outputFile, json + "\n", "utf-8");
  } else {
    console.log(json);
  }
  return json;
}

function buildRules(findings: Finding[]): SarifRule[] {
  const byId = new Map<string, Finding>();
  for (const finding of findings) {
    if (!byId.has(finding.id)) byId.set(finding.id, finding);
  }

  return [...byId.values()].map((finding) => ({
    id: finding.id,
    name: finding.title,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description },
    help: finding.remediation
      ? { text: finding.remediation, markdown: finding.remediation }
      : undefined,
    properties: {
      category: finding.category,
      precision: "medium",
      "security-severity": SECURITY_SEVERITY[finding.severity],
      tags: ["security", finding.category, finding.severity],
    },
  }));
}

function toSarifResult(finding: Finding, target: string): SarifResult {
  const location = finding.file
    ? {
        physicalLocation: {
          artifactLocation: { uri: toSarifUri(finding.file, target) },
          region: finding.line ? { startLine: finding.line } : undefined,
        },
      }
    : undefined;

  return {
    ruleId: finding.id,
    level: toSarifLevel(finding.severity),
    message: { text: `${finding.title}: ${finding.description}` },
    fingerprints: { breachscope: finding.fingerprint! },
    locations: location ? [location] : undefined,
    properties: {
      severity: finding.severity,
      category: finding.category,
      tool: finding.tool,
      references: finding.references,
    },
  };
}

function toSarifLevel(severity: Finding["severity"]): SarifResult["level"] {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "note";
}

function toSarifUri(file: string, target: string): string {
  const normalized = file.replace(/\\/g, "/");
  if (!path.isAbsolute(file)) return normalized;

  try {
    return path.relative(target, file).replace(/\\/g, "/");
  } catch {
    return normalized;
  }
}
