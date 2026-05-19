import crypto from "crypto";
import fs from "fs";
import type { Finding } from "./types.js";

export interface BaselineEntry {
  fingerprint: string;
  id: string;
  title: string;
  severity: Finding["severity"];
  category: Finding["category"];
  file?: string;
  line?: number;
  tool?: string;
}

export interface FindingBaseline {
  version: 1;
  generatedAt: string;
  entries: BaselineEntry[];
}

export function fingerprintFinding(finding: Finding): string {
  if (finding.fingerprint) return finding.fingerprint;

  const parts = [
    finding.id,
    finding.title,
    finding.severity,
    finding.category,
    finding.tool ?? "",
    normalizePath(finding.file ?? ""),
    String(finding.line ?? ""),
    normalizeEvidence(finding.detail ?? ""),
  ];

  return crypto.createHash("sha256").update(parts.join("\0")).digest("hex");
}

export function attachFingerprints(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({
    ...finding,
    fingerprint: fingerprintFinding(finding),
  }));
}

export function createBaseline(findings: Finding[], generatedAt = new Date()): FindingBaseline {
  return {
    version: 1,
    generatedAt: generatedAt.toISOString(),
    entries: attachFingerprints(findings).map((finding) => ({
      fingerprint: finding.fingerprint!,
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      file: finding.file,
      line: finding.line,
      tool: finding.tool,
    })),
  };
}

export function writeBaseline(path: string, findings: Finding[]): FindingBaseline {
  const baseline = createBaseline(findings);
  fs.writeFileSync(path, JSON.stringify(baseline, null, 2) + "\n", "utf-8");
  return baseline;
}

export function loadBaseline(path: string): FindingBaseline {
  const parsed = JSON.parse(fs.readFileSync(path, "utf-8")) as Partial<FindingBaseline>;
  if (parsed.version !== 1 || !Array.isArray(parsed.entries)) {
    throw new Error(`Invalid BreachScope baseline file: ${path}`);
  }
  return parsed as FindingBaseline;
}

export function filterNewFindings(findings: Finding[], baseline: FindingBaseline): Finding[] {
  const known = new Set(baseline.entries.map((entry) => entry.fingerprint));
  return attachFingerprints(findings).filter((finding) => !known.has(finding.fingerprint!));
}

function normalizePath(file: string): string {
  return file.replace(/\\/g, "/").toLowerCase();
}

function normalizeEvidence(detail: string): string {
  return detail.replace(/\s+/g, " ").trim().slice(0, 500);
}
