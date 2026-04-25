import chalk from "chalk";
import type { AgentResult } from "../core/types.js";
import type { ReportSynthesis } from "../agents/report.js";

export function renderAIReport(results: AgentResult[], synthesis: ReportSynthesis | null): void {
  console.log("\n" + chalk.bold.white("━".repeat(65)));
  console.log(chalk.bold.white("  BREACHSCOPE AI REPORT"));
  console.log(chalk.bold.white("━".repeat(65)));

  // Executive summary
  if (synthesis?.executiveSummary) {
    console.log("\n" + chalk.bold("Executive Summary"));
    console.log(chalk.white(synthesis.executiveSummary));
  }

  // Top priority
  if (synthesis?.topPriority) {
    console.log("\n" + chalk.bgRed.white.bold("  TOP PRIORITY  "));
    console.log(chalk.red(synthesis.topPriority));
  }

  // Attack chains
  if (synthesis?.attackChains?.length) {
    console.log("\n" + chalk.bold.yellow("Attack Chains Identified"));
    for (const chain of synthesis.attackChains) {
      const badge = chain.severity === "critical"
        ? chalk.bgRed.white(` ${chain.severity.toUpperCase()} `)
        : chalk.bgYellow.black(` ${chain.severity.toUpperCase()} `);
      console.log(`\n  ${badge}  ${chalk.bold(chain.title)}`);
      console.log(`  Impact: ${chalk.white(chain.impact)}`);
      chain.steps.forEach((step, i) => {
        console.log(`  ${chalk.gray(`${i + 1}.`)} ${step}`);
      });
    }
  }

  // Findings by agent
  const allFindings = synthesis?.deduplicatedFindings ?? results.flatMap((r) => r.findings);

  if (allFindings.length === 0) {
    console.log(chalk.green("\n  ✓ No findings detected.\n"));
    return;
  }

  console.log(`\n${chalk.bold("Findings")}  ${chalk.gray(`(${allFindings.length} total after deduplication)`)}`);

  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const colors: Record<string, (s: string) => string> = {
    critical: (s) => chalk.bgRed.white.bold(s),
    high: (s) => chalk.red.bold(s),
    medium: (s) => chalk.yellow(s),
    low: (s) => chalk.cyan(s),
    info: (s) => chalk.gray(s),
  };

  for (const sev of severityOrder) {
    const group = allFindings.filter((f) => f.severity === sev);
    if (!group.length) continue;

    const badge = (colors[sev] ?? chalk.white)(` ${sev.toUpperCase()} `);
    console.log(`\n  ${badge}`);

    for (const f of group) {
      console.log(`\n  ${chalk.bold(f.title)}`);
      if (f.file) console.log(`  ${chalk.gray("File:")} ${f.file}${f.line ? `:${f.line}` : ""}`);
      if (f.tool) console.log(`  ${chalk.gray("Via:")}  ${f.tool}`);
      console.log(`  ${chalk.gray("Desc:")} ${f.description}`);
      if (f.remediation) console.log(`  ${chalk.green("Fix: ")} ${f.remediation}`);
    }
  }

  // Agent stats
  console.log("\n" + chalk.bold.white("━".repeat(65)));
  console.log(chalk.bold("Agent Run Summary"));
  let totalTokens = 0;
  for (const result of results) {
    totalTokens += result.tokensUsed;
    const label = result.agent.padEnd(12);
    const findings = String(result.findings.length).padStart(3);
    const sources = result.sourcesCrawled.length;
    console.log(
      `  ${chalk.cyan(label)} ${findings} finding(s)  ${chalk.gray(`${sources} source(s) crawled  ${result.tokensUsed} tokens`)}`
    );
  }
  console.log(chalk.gray(`\n  Total tokens used: ${totalTokens}`));
  console.log();
}
