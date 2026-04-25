import chalk from "chalk";
import { table } from "table";
import type { ScanResult, Finding, Severity } from "../core/types.js";
import { logger } from "../core/logger.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  info: (s) => chalk.gray(s),
};

export function renderConsoleReport(result: ScanResult): void {
  const { findings, summary } = result;

  logger.blank();
  console.log(chalk.bold.white("━".repeat(60)));
  console.log(chalk.bold.white("  BREACHSCOPE REPORT"));
  console.log(chalk.bold.white("━".repeat(60)));

  if (findings.length === 0) {
    console.log(chalk.green("\n  ✓ No issues detected.\n"));
    return;
  }

  // Summary bar
  console.log();
  const summaryParts = SEVERITY_ORDER
    .filter((s) => summary[s] > 0)
    .map((s) => SEVERITY_COLOR[s](` ${summary[s]} ${s.toUpperCase()} `));
  console.log("  " + summaryParts.join("  "));
  console.log();

  // Group by severity
  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;

    const badge = SEVERITY_COLOR[severity](` ${severity.toUpperCase()} `);
    console.log(`\n  ${badge}\n`);

    for (const finding of group) {
      renderFinding(finding);
    }
  }

  // Summary table
  const tableData = [
    ["Severity", "Count"].map((h) => chalk.bold(h)),
    ...SEVERITY_ORDER
      .filter((s) => summary[s] > 0)
      .map((s) => [SEVERITY_COLOR[s](s.toUpperCase()), String(summary[s])]),
    [chalk.bold("TOTAL"), chalk.bold(String(summary.total))],
  ];

  console.log("\n" + table(tableData, {
    border: {
      topBody: "─", topJoin: "┬", topLeft: "┌", topRight: "┐",
      bottomBody: "─", bottomJoin: "┴", bottomLeft: "└", bottomRight: "┘",
      bodyLeft: "│", bodyRight: "│", bodyJoin: "│",
      joinBody: "─", joinLeft: "├", joinRight: "┤", joinJoin: "┼",
    },
  }));

  const elapsed = ((result.completedAt.getTime() - result.startedAt.getTime()) / 1000).toFixed(1);
  console.log(chalk.gray(`  Scan completed in ${elapsed}s\n`));
}

function renderFinding(f: Finding): void {
  console.log(`  ${chalk.bold(f.title)}`);
  if (f.file) console.log(`  ${chalk.gray("File:")} ${f.file}${f.line ? `:${f.line}` : ""}`);
  if (f.tool) console.log(`  ${chalk.gray("Tool:")} ${f.tool}`);
  console.log(`  ${chalk.gray("Desc:")} ${f.description}`);
  if (f.detail) console.log(`  ${chalk.gray("Code:")} ${chalk.italic(f.detail)}`);
  if (f.remediation) console.log(`  ${chalk.green("Fix: ")} ${f.remediation}`);
  if (f.references?.length) {
    console.log(`  ${chalk.blue("Refs:")} ${f.references.join(", ")}`);
  }
  console.log();
}
