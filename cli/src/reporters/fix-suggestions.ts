import fs from "fs";
import type { Finding, ScanResult } from "../core/types.js";

export function renderFixSuggestionsFromScanFile(scanFile: string, outputFile?: string): string {
  const result = JSON.parse(fs.readFileSync(scanFile, "utf-8")) as ScanResult;
  const markdown = renderFixSuggestions(result);
  if (outputFile) fs.writeFileSync(outputFile, markdown, "utf-8");
  else console.log(markdown);
  return markdown;
}

export function renderFixSuggestions(result: ScanResult): string {
  const findings = [...result.findings].sort((a, b) => severityRank(a) - severityRank(b));
  const lines = [
    "# BreachScope Fix Suggestions",
    "",
    `Target: ${result.target}`,
    `Findings: ${findings.length}`,
    "",
  ];

  for (const finding of findings) {
    lines.push(`## ${finding.severity.toUpperCase()} - ${finding.title}`);
    lines.push("");
    if (finding.file) lines.push(`Location: \`${finding.file}${finding.line ? `:${finding.line}` : ""}\``);
    lines.push(`Category: \`${finding.category}\``);
    lines.push("");
    lines.push(finding.description);
    lines.push("");
    lines.push("Suggested fix:");
    lines.push("");
    lines.push(`- ${suggestFix(finding)}`);
    if (finding.remediation) lines.push(`- Existing remediation: ${finding.remediation}`);
    if (finding.references?.length) {
      lines.push("- References:");
      for (const ref of finding.references.slice(0, 5)) lines.push(`  - ${ref}`);
    }
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function suggestFix(finding: Finding): string {
  const text = `${finding.title} ${finding.description} ${finding.detail ?? ""}`.toLowerCase();
  if (text.includes("sql injection") || text.includes("sqli")) return "Replace string-built SQL with parameterized queries and add regression tests for malicious input.";
  if (text.includes("xss")) return "HTML-encode untrusted output, sanitize rich text, and add browser tests for script payloads.";
  if (text.includes("secret") || text.includes("api key") || text.includes("token")) return "Rotate the exposed credential, move it to a secret manager, and add secret scanning to CI.";
  if (text.includes("dependency") || text.includes("cve") || text.includes("osv")) return "Upgrade to the patched version, regenerate the lockfile, and run the test suite before merging.";
  if (text.includes("cors")) return "Replace wildcard CORS with an explicit allowlist and validate credentials mode.";
  if (text.includes("jwt")) return "Enforce strong signing algorithms, key rotation, issuer/audience checks, and short token lifetimes.";
  if (text.includes("docker")) return "Harden the container with dropped capabilities, no-new-privileges, non-root users, and secret mounts.";
  return "Follow the remediation guidance, add a focused regression test, and document any accepted risk with an expiry date.";
}

function severityRank(finding: Finding): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[finding.severity];
}
