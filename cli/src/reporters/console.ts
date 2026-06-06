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
  const triage = getTriageMetadata(result);

  logger.blank();
  console.log(chalk.bold.white("━".repeat(60)));
  console.log(chalk.bold.white("  BREACHSCOPE REPORT"));
  console.log(chalk.bold.white("━".repeat(60)));

  if (findings.length === 0) {
    const hiddenText = triage && (triage.review > 0 || triage.hidden > 0)
      ? chalk.gray(` ${triage.review} review item(s), ${triage.hidden} hidden noise item(s).`)
      : "";
    console.log(chalk.green("\n  ✓ No actionable issues detected.") + hiddenText + "\n");
    return;
  }

  // Summary bar
  console.log();
  const summaryParts = SEVERITY_ORDER
    .filter((s) => summary[s] > 0)
    .map((s) => SEVERITY_COLOR[s](` ${summary[s]} ${s.toUpperCase()} `));
  console.log("  " + summaryParts.join("  "));
  if (triage && (triage.review > 0 || triage.hidden > 0)) {
    console.log(chalk.gray(`  Triage: ${triage.review} review item(s), ${triage.hidden} hidden by default. Use --show-noise to include all findings or --all-cves for suppressed CVE detail.`));
    for (const title of triage.reviewTitles.slice(0, 5)) {
      console.log(chalk.gray(`    review: ${title}`));
    }
  }
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
  if (f.triageDecision || f.confidence || f.evidenceStrength) {
    const bits = [
      f.triageDecision ? `triage=${f.triageDecision}` : null,
      f.confidence ? `confidence=${f.confidence}` : null,
      f.evidenceStrength ? `evidence=${f.evidenceStrength}` : null,
    ].filter(Boolean);
    console.log(`  ${chalk.gray("Signal:")} ${bits.join(" | ")}`);
  }
  console.log(`  ${chalk.gray("Desc:")} ${f.description}`);
  if (f.triageReason) console.log(`  ${chalk.gray("Reason:")} ${f.triageReason}`);
  if (f.detail) console.log(`  ${chalk.gray("Code:")} ${chalk.italic(f.detail)}`);
  if (f.remediation) console.log(`  ${chalk.green("Fix: ")} ${f.remediation}`);
  if (f.references?.length) {
    console.log(`  ${chalk.blue("Refs:")} ${f.references.join(", ")}`);
  }
  console.log();
}

function getTriageMetadata(result: ScanResult): { review: number; hidden: number; reviewTitles: string[] } | null {
  const governance = result.metadata["governance"];
  if (!governance || typeof governance !== "object") return null;
  const triage = (governance as Record<string, unknown>)["triage"];
  if (!triage || typeof triage !== "object") return null;
  const record = triage as Record<string, unknown>;
  const review = typeof record["review"] === "number" ? record["review"] : 0;
  const hidden = typeof record["hidden"] === "number" ? record["hidden"] : 0;
  const reviewFindings = Array.isArray(record["reviewFindings"]) ? record["reviewFindings"] : [];
  const reviewTitles = reviewFindings
    .map((item) => typeof item === "object" && item !== null ? (item as Record<string, unknown>)["title"] : null)
    .filter((title): title is string => typeof title === "string");
  return { review, hidden, reviewTitles };
}
