import fs from "fs";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

// Known dangerous script injection patterns
const DANGEROUS_SCRIPT_PATTERNS = [
  /curl\s+.*\|\s*(ba)?sh/,
  /wget\s+.*\|\s*(ba)?sh/,
  /eval\s*\(/,
  /base64\s+--decode/,
  /python\s+-c/,
  /node\s+-e/,
];

// Packages with known supply-chain incidents
const FLAGGED_PACKAGES: Record<string, { reason: string; severity: Finding["severity"] }> = {
  // 2018
  "event-stream":   { reason: "Supply chain attack (2018) — maintainer handed off to attacker who injected encrypted payload targeting Copay Bitcoin wallet. 2M weekly downloads.", severity: "critical" },
  "flatmap-stream": { reason: "Malicious payload vehicle injected via event-stream attack (2018). Contains encrypted code that stole Bitcoin private keys.", severity: "critical" },
  // 2021
  "ua-parser-js":   { reason: "Hijacked package (Oct 2021) — attacker published malicious versions with crypto miner + credential stealer. 8M weekly downloads.", severity: "critical" },
  "coa":            { reason: "Hijacked package (Oct 2021, same batch as ua-parser-js) — malicious versions published containing a password stealer targeting Windows.", severity: "critical" },
  "rc":             { reason: "Hijacked package (Oct 2021, same batch as ua-parser-js) — malicious versions published with a credential stealer payload.", severity: "critical" },
  // 2022
  "colors":         { reason: "Intentional sabotage by maintainer Marak Squiress (Jan 2022) — infinite loop added to protest unpaid open-source labor. 23M weekly downloads.", severity: "high" },
  "faker":          { reason: "Intentional sabotage by maintainer Marak Squiress (Jan 2022) — package corrupted in protest. Broke thousands of downstream projects.", severity: "high" },
  "node-ipc":       { reason: "Malicious code deliberately shipped by maintainer (2022) — overwrote files on machines with Russian/Belarusian IPs. Used in vue-cli.", severity: "critical" },
};

export async function scanNpm(pkgPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const raw = fs.readFileSync(pkgPath, "utf-8");
  let pkg: PackageJson;

  try {
    pkg = JSON.parse(raw);
  } catch {
    logger.warn("Could not parse package.json");
    return findings;
  }

  // Check lifecycle scripts for injection
  for (const [script, cmd] of Object.entries(pkg.scripts ?? {})) {
    for (const pattern of DANGEROUS_SCRIPT_PATTERNS) {
      if (pattern.test(cmd)) {
        findings.push({
          id: `npm-script-injection-${script}`,
          title: `Suspicious lifecycle script: ${script}`,
          severity: "high",
          category: "dependency",
          description: `The "${script}" script contains a pattern commonly used in supply chain attacks.`,
          detail: cmd,
          remediation: "Audit the script and ensure it only executes trusted code. Avoid piping remote content to a shell.",
          file: pkgPath,
          references: ["https://docs.npmjs.com/cli/v10/using-npm/scripts"],
        });
        break;
      }
    }
  }

  // Check for flagged packages
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };

  for (const [dep] of Object.entries(allDeps)) {
    if (FLAGGED_PACKAGES[dep]) {
      const { reason, severity } = FLAGGED_PACKAGES[dep];
      findings.push({
        id: `npm-flagged-${dep}`,
        title: `Flagged package: ${dep}`,
        severity,
        category: "dependency",
        description: reason,
        remediation: "Remove or replace this dependency. Audit your lockfile for any transitive inclusion.",
        file: pkgPath,
        tool: "npm",
      });
    }
  }

  // Check for wildcard/unpinned versions
  for (const [dep, version] of Object.entries(pkg.dependencies ?? {})) {
    if (version === "*" || version === "latest") {
      findings.push({
        id: `npm-unpinned-${dep}`,
        title: `Unpinned dependency: ${dep}@${version}`,
        severity: "medium",
        category: "dependency",
        description: "Wildcard or 'latest' versions allow arbitrary package versions to be installed, enabling supply chain substitution.",
        remediation: `Pin to a specific version or range: "^x.y.z"`,
        file: pkgPath,
        tool: "npm",
      });
    }
  }

  return findings;
}
