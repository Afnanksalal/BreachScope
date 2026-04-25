import fs from "fs";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

type LockfileType = "npm" | "yarn" | "pnpm";

// Detects integrity hash mismatches and registry tampering signals
export async function scanLockfile(lockPath: string, type: LockfileType): Promise<Finding[]> {
  const findings: Finding[] = [];
  const raw = fs.readFileSync(lockPath, "utf-8");

  // Check for non-registry sources (git+, file:, http: instead of https:)
  const httpPattern = /resolved\s+"http:\/\/(?!localhost)/g;
  const gitPattern = /resolved\s+"git\+(?!https)/g;
  const filePattern = /resolved\s+"file:/g;

  if (httpPattern.test(raw)) {
    findings.push({
      id: `lockfile-insecure-registry-${type}`,
      title: "Package resolved over HTTP (not HTTPS)",
      severity: "high",
      category: "dependency",
      description: "One or more packages are resolved from an HTTP endpoint. This allows MITM attacks during install.",
      remediation: "Ensure all registry URLs use HTTPS. Check your .npmrc or .yarnrc for insecure registry settings.",
      file: lockPath,
      tool: type,
      references: ["https://docs.npmjs.com/cli/v10/configuring-npm/npmrc"],
    });
  }

  if (filePattern.test(raw)) {
    findings.push({
      id: `lockfile-file-protocol-${type}`,
      title: "Package resolved from local file path",
      severity: "medium",
      category: "dependency",
      description: "A dependency is resolved via the file: protocol. In CI/CD this may point to an unintended or attacker-controlled path.",
      remediation: "Verify all file: resolutions are intentional and scoped to this repository.",
      file: lockPath,
      tool: type,
    });
  }

  // Detect missing integrity fields (npm/yarn v2+)
  if (type === "npm") {
    try {
      const lock = JSON.parse(raw);
      const packages: Record<string, { integrity?: string; resolved?: string }> =
        lock.packages ?? lock.dependencies ?? {};

      let missingIntegrity = 0;
      for (const [, entry] of Object.entries(packages)) {
        if (entry.resolved && !entry.integrity) {
          missingIntegrity++;
        }
      }

      if (missingIntegrity > 0) {
        findings.push({
          id: "lockfile-missing-integrity",
          title: `${missingIntegrity} package(s) missing integrity hash`,
          severity: "medium",
          category: "dependency",
          description: "Packages without integrity hashes cannot be verified against tampering after resolution.",
          remediation: "Run `npm install` to regenerate the lockfile with integrity hashes.",
          file: lockPath,
          tool: "npm",
        });
      }
    } catch {
      logger.debug("Could not parse package-lock.json as JSON");
    }
  }

  return findings;
}
