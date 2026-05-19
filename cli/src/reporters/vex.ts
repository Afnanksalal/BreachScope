import fs from "fs";
import crypto from "crypto";
import type { Finding, ScanResult } from "../core/types.js";
import { attachFingerprints } from "../core/baseline.js";

interface OpenVexDocument {
  "@context": string;
  "@id": string;
  author: string;
  timestamp: string;
  version: number;
  statements: OpenVexStatement[];
}

interface OpenVexStatement {
  vulnerability: { name: string };
  products: Array<{ "@id": string }>;
  status: "affected" | "not_affected" | "fixed" | "under_investigation";
  justification?: string;
  impact_statement?: string;
  timestamp: string;
}

export function renderVexReport(result: ScanResult, outputFile?: string): string {
  const findings = attachFingerprints(result.findings);
  const timestamp = new Date().toISOString();
  const doc: OpenVexDocument = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:breachscope:vex:${hash(`${result.target}:${timestamp}`)}`,
    author: "BreachScope",
    timestamp,
    version: 1,
    statements: findings
      .filter(isVulnerabilityFinding)
      .map((finding) => toStatement(finding, result.target, timestamp)),
  };

  const json = JSON.stringify(doc, null, 2);
  if (outputFile) {
    fs.writeFileSync(outputFile, json + "\n", "utf-8");
  } else {
    console.log(json);
  }
  return json;
}

export function renderVexFromScanFile(scanFile: string, outputFile?: string): string {
  const parsed = JSON.parse(fs.readFileSync(scanFile, "utf-8")) as ScanResult;
  parsed.startedAt = new Date(parsed.startedAt);
  parsed.completedAt = new Date(parsed.completedAt);
  return renderVexReport(parsed, outputFile);
}

function toStatement(finding: Finding, target: string, timestamp: string): OpenVexStatement {
  return {
    vulnerability: { name: extractVulnerabilityName(finding) },
    products: [{ "@id": target }],
    status: finding.vexStatus ?? "under_investigation",
    justification: finding.vexStatus === "not_affected" ? "vulnerable_code_not_present" : undefined,
    impact_statement: finding.description,
    timestamp,
  };
}

function isVulnerabilityFinding(finding: Finding): boolean {
  const text = `${finding.id} ${finding.title} ${finding.detail ?? ""}`;
  return /CVE-\d{4}-\d+|GHSA-[a-z0-9-]+|OSV|vulnerability/i.test(text);
}

function extractVulnerabilityName(finding: Finding): string {
  const text = `${finding.id} ${finding.title} ${finding.detail ?? ""}`;
  return text.match(/CVE-\d{4}-\d+/i)?.[0]
    ?? text.match(/GHSA-[a-z0-9-]+/i)?.[0]
    ?? finding.id;
}

function hash(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}
