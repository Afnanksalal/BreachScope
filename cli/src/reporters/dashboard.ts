import chalk from "chalk";
import type { SubchainScanResult } from "../core/types.js";

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  info: (s) => chalk.gray(s),
};

function riskBadge(score: number): string {
  if (score >= 75) return chalk.bgRed.white.bold(` ${score} `);
  if (score >= 50) return chalk.red.bold(` ${score} `);
  if (score >= 25) return chalk.yellow(` ${score} `);
  return chalk.green(` ${score} `);
}

function kindBadge(kind: string): string {
  if (kind === "oss") return chalk.cyan("OSS");
  if (kind === "saas") return chalk.magenta("SaaS");
  if (kind === "hybrid") return chalk.yellow("Hybrid");
  return chalk.gray("?");
}

function bar(score: number, width = 20): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const color = score >= 75 ? chalk.red : score >= 50 ? chalk.yellow : chalk.green;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
}

export function renderDashboard(result: SubchainScanResult): void {
  const { toolResults, mode, depthReached } = result;

  console.log("\n" + chalk.bold.white("═".repeat(70)));
  console.log(chalk.bold.white("  BREACHSCOPE SUB-TOOLCHAIN RISK DASHBOARD"));
  console.log(chalk.bold.white("═".repeat(70)));
  console.log(chalk.gray(`  Mode: ${mode.toUpperCase()}  │  Depth: ${depthReached}  │  Tools scanned: ${toolResults.length}`));
  console.log();

  // Sort by risk score descending
  const sorted = [...toolResults].sort((a, b) => b.riskScore - a.riskScore);

  // Risk overview table
  console.log(chalk.bold("  Tool Risk Overview\n"));
  console.log(
    chalk.gray("  " + "Package".padEnd(40) + "Kind".padEnd(9) + "Risk".padEnd(8) + "Bar")
  );
  console.log(chalk.gray("  " + "─".repeat(65)));

  for (const r of sorted) {
    const name = r.tool.name.length > 38 ? r.tool.name.slice(0, 35) + "..." : r.tool.name;
    const depthIndicator = r.tool.depth > 0 ? chalk.gray(`  ${"└─".repeat(r.tool.depth)} `) : "  ";
    console.log(
      depthIndicator +
      name.padEnd(40 - r.tool.depth * 2) +
      kindBadge(r.tool.kind).padEnd(9) +
      riskBadge(r.riskScore).padEnd(8) +
      "  " + bar(r.riskScore)
    );
  }

  // Scorecard highlights
  const withScorecard = sorted.filter((r) => r.scorecard);
  if (withScorecard.length) {
    console.log("\n" + chalk.bold("  OpenSSF Scorecard\n"));
    for (const r of withScorecard) {
      const sc = r.scorecard!;
      const color = sc.score < 4 ? chalk.red : sc.score < 7 ? chalk.yellow : chalk.green;
      console.log(`  ${r.tool.name.padEnd(40)} Score: ${color(sc.score.toFixed(1).padStart(4))}/10`);
    }
  }

  // OSV vulnerability summary
  const withVulns = sorted.filter((r) => r.osvVulnerabilities.length > 0);
  if (withVulns.length) {
    console.log("\n" + chalk.bold("  OSV Vulnerabilities\n"));
    for (const r of withVulns) {
      console.log(
        `  ${chalk.red("●")} ${r.tool.name}  ${chalk.red(`${r.osvVulnerabilities.length} vuln(s)`)}` +
        `  ${chalk.gray(r.osvVulnerabilities.map((v) => v.id).slice(0, 3).join(", ") + (r.osvVulnerabilities.length > 3 ? "..." : ""))}`
      );
    }
  }

  // All findings grouped by severity
  const allFindings = result.allFindings;
  if (allFindings.length > 0) {
    console.log("\n" + chalk.bold("  Findings\n"));

    for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
      const group = allFindings.filter((f) => f.severity === sev);
      if (!group.length) continue;

      const badge = SEVERITY_COLOR[sev]!(` ${sev.toUpperCase()} `);
      console.log(`\n  ${badge}`);

      for (const f of group) {
        console.log(`\n    ${chalk.bold(f.title)}`);
        if (f.tool) console.log(`    ${chalk.gray("Tool:")} ${f.tool}`);
        console.log(`    ${chalk.gray("Desc:")} ${f.description}`);
        if (f.remediation) console.log(`    ${chalk.green("Fix: ")} ${f.remediation}`);
      }
    }
  } else {
    console.log(chalk.green("\n  ✓ No findings detected across all scanned tools.\n"));
  }

  // Shared / deduped dependencies
  const sharedEntries = Object.entries(result.sharedPackages ?? {});
  if (sharedEntries.length > 0) {
    console.log("\n" + chalk.bold("  Shared Dependencies (deduped — scanned once)\n"));
    console.log(chalk.gray("  " + "Package".padEnd(36) + "Required by"));
    console.log(chalk.gray("  " + "─".repeat(65)));
    for (const [pkg, parents] of sharedEntries.sort((a, b) => b[1].length - a[1].length)) {
      const parentList = parents.slice(0, 4).join(", ") + (parents.length > 4 ? ` +${parents.length - 4} more` : "");
      const name = pkg.length > 34 ? pkg.slice(0, 31) + "..." : pkg;
      console.log(`  ${chalk.cyan("◈")} ${name.padEnd(34)}  ${chalk.gray(parentList)}`);
    }
  }

  // AI summaries
  const withSummary = sorted.filter((r) => r.aiSummary && !r.aiSummary.includes("unavailable"));
  if (withSummary.length) {
    console.log("\n" + chalk.bold("  AI Risk Summaries\n"));
    for (const r of withSummary.slice(0, 5)) {
      console.log(`  ${chalk.bold(r.tool.name)}`);
      console.log(`  ${chalk.gray(r.aiSummary)}\n`);
    }
  }

  // Final stats
  console.log("\n" + chalk.bold.white("═".repeat(70)));
  const critical = allFindings.filter((f) => f.severity === "critical").length;
  const high = allFindings.filter((f) => f.severity === "high").length;
  const topRisk = sorted[0];
  console.log(
    `  ${chalk.red(`${critical} critical`)}  ${chalk.yellow(`${high} high`)}  ` +
    `${chalk.gray(`${allFindings.length} total`)}` +
    (topRisk ? `  │  Highest risk: ${chalk.bold(topRisk.tool.name)} (${topRisk.riskScore}/100)` : "")
  );
  console.log();
}
