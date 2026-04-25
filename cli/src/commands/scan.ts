import ora from "ora";
import chalk from "chalk";
import { loadConfig } from "../core/config.js";
import { logger } from "../core/logger.js";
import { fetchRemoteConfig } from "../core/remote-config.js";
import type { ScanOptions, ScanResult, ScanSummary, Finding } from "../core/types.js";
import { runDependencyScanner } from "../scanners/dependency/index.js";
import { runToolchainScanner } from "../scanners/toolchain/index.js";
import { runCodeAudit } from "../scanners/code/index.js";
import { runBlackboxProbe } from "../scanners/blackbox/index.js";
import { runSmokeTests } from "../scanners/smoke/index.js";
import { renderConsoleReport } from "../reporters/console.js";
import { renderJsonReport } from "../reporters/json.js";
import { renderDashboard } from "../reporters/dashboard.js";
import { buildAgentContext } from "../core/context.js";
import { runOrchestrator } from "../agents/orchestrator.js";
import { renderAIReport } from "../reporters/ai-console.js";
import { lastSynthesis } from "../agents/report.js";
import { runSubchainScan } from "../engine/index.js";
import { discoverServices } from "../core/services.js";
import { promptText, promptSecret, promptConfirm, SecureStore } from "../core/interactive.js";
import { runLiveProbe } from "../agents/live-probe.js";

const BANNER = `
  ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
  ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
  ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
  ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ███████╗██║     ██║   ██║██████╔╝█████╗
  ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
`;

export async function runScan(opts: ScanOptions): Promise<void> {
  const config = loadConfig(opts.config);
  const cwd = process.cwd();
  const startedAt = new Date();
  const target = opts.target ?? "all";
  const mode = opts.mode ?? "basic";
  const url = opts.url;

  if (opts.verbose) logger.setVerbose(true);

  // Pull encrypted API keys from dashboard if authenticated
  if (opts.ai) {
    const remote = await fetchRemoteConfig();
    if (remote) {
      if (!process.env.OPENAI_API_KEY && remote.openaiKey) process.env.OPENAI_API_KEY = remote.openaiKey;
      if (!process.env.FIRECRAWL_API_KEY && remote.firecrawlKey) process.env.FIRECRAWL_API_KEY = remote.firecrawlKey;
    }
  }

  console.log(chalk.dim(BANNER));
  console.log(chalk.gray(`  Mode: ${chalk.white(mode.toUpperCase())}  │  Target: ${chalk.white(target.toUpperCase())}${url ? `  │  URL: ${chalk.white(url)}` : ""}`));
  logger.blank();

  const findings: Finding[] = [];

  // ── Static scanners ───────────────────────────────────────────────────────
  if (target === "all" || target === "dependency") {
    const spinner = ora("Scanning dependencies...").start();
    try {
      const result = await runDependencyScanner(cwd);
      findings.push(...result);
      spinner.succeed(`Dependency scan — ${result.length} issue(s)`);
    } catch (e) {
      spinner.fail("Dependency scan failed");
      logger.debug(e);
    }
  }

  if (target === "all" || target === "code") {
    const spinner = ora("Auditing source code...").start();
    try {
      const result = await runCodeAudit(cwd);
      findings.push(...result);
      spinner.succeed(`Code audit — ${result.length} issue(s)`);
    } catch (e) {
      spinner.fail("Code audit failed");
      logger.debug(e);
    }
  }

  if (target === "all" || target === "toolchain") {
    const spinner = ora("Probing toolchain...").start();
    try {
      const result = await runToolchainScanner(config.toolchain);
      findings.push(...result);
      spinner.succeed(`Toolchain scan — ${result.length} issue(s)`);
    } catch (e) {
      spinner.fail("Toolchain scan failed");
      logger.debug(e);
    }
  }

  if (url) {
    if (target === "all" || target === "blackbox") {
      const spinner = ora(`Blackbox probing ${url}...`).start();
      try {
        const result = await runBlackboxProbe({ url, verbose: opts.verbose });
        findings.push(...result);
        spinner.succeed(`Blackbox probe — ${result.length} issue(s)`);
      } catch (e) {
        spinner.fail("Blackbox probe failed");
        logger.debug(e);
      }
    }

    if (target === "all" || target === "smoke") {
      const spinner = ora(`Smoke testing ${url}...`).start();
      try {
        const result = await runSmokeTests({ url, verbose: opts.verbose });
        findings.push(...result);
        spinner.succeed(`Smoke tests — ${result.length} issue(s)`);
      } catch (e) {
        spinner.fail("Smoke tests failed");
        logger.debug(e);
      }
    }
  } else if (target === "blackbox" || target === "smoke") {
    logger.warn("Blackbox/smoke scanning requires a --url flag");
  }

  // ── Sub-toolchain scan (always runs unless explicitly targeting single type) ──
  const shouldRunSubchain = target === "all" || target === "dependency";
  if (shouldRunSubchain) {
    try {
      const subchainResult = await runSubchainScan(cwd, mode, config.subchain);
      findings.push(...subchainResult.allFindings);
      renderDashboard(subchainResult);
    } catch (e) {
      logger.error(`Sub-chain scan failed: ${e}`);
      logger.debug(e);
    }
  }

  // ── Interactive live probe ─────────────────────────────────────────────────
  if (opts.ai && process.stdin.isTTY) {
    logger.blank();
    logger.section("Live Service Probe");

    // Collect installed packages from package.json(s) in cwd
    let installedPackages: string[] = [];
    try {
      const pkgPath = `${cwd}/package.json`;
      const { default: fs } = await import("fs");
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        installedPackages = [
          ...Object.keys(pkg.dependencies ?? {}),
          ...Object.keys(pkg.devDependencies ?? {}),
        ];
      }
    } catch {
      // continue without package list
    }

    const discovered = discoverServices(cwd, installedPackages);

    if (discovered.length === 0) {
      console.log(chalk.gray("  No third-party services detected in this project."));
    } else {
      console.log(chalk.gray(`  Detected ${chalk.white(discovered.length)} service(s) in your codebase:\n`));
      for (const svc of discovered) {
        const badge = svc.confidence === "both" ? chalk.green("●") : chalk.yellow("◐");
        console.log(`  ${badge} ${chalk.white(svc.definition.name)} ${chalk.gray(`(${svc.definition.category})`)}`);
      }
      logger.blank();

      for (const svc of discovered) {
        const def = svc.definition;
        const confirm = await promptConfirm(`Probe live ${def.name} environment?`);
        if (!confirm) continue;

        const store = new SecureStore();
        let allFieldsFilled = true;

        for (const field of def.fields) {
          // Try env hint pre-fill
          const envValue = field.envHint ? process.env[field.envHint] : undefined;

          if (envValue) {
            console.log(chalk.gray(`  ${field.label}: `) + chalk.dim("[from env]"));
            store.set(field.key, envValue);
            continue;
          }

          // Prompt user
          const promptFn = field.secret ? promptSecret : promptText;
          const value = await promptFn(`  ${field.label}: `);

          if (!value && !field.label.includes("optional")) {
            console.log(chalk.yellow(`  Skipping — ${field.label} is required.`));
            allFieldsFilled = false;
            break;
          }

          if (value) store.set(field.key, value);
        }

        if (!allFieldsFilled) {
          store.destroy();
          continue;
        }

        const spinner = ora(`AI probing ${def.name}...`).start();
        try {
          const result = await runLiveProbe(def, store.toRecord());
          findings.push(...result.findings);
          spinner.succeed(`${def.name} probe — ${result.findings.length} issue(s) (${result.tokensUsed.toLocaleString()} tokens)`);
        } catch (e) {
          spinner.fail(`${def.name} probe failed`);
          logger.debug(e);
        } finally {
          store.destroy();
        }

        logger.blank();
      }
    }
  }

  // ── AI multi-agent layer ───────────────────────────────────────────────────
  if (opts.ai) {
    logger.section("AI Multi-Agent Analysis");
    const ctx = await buildAgentContext(cwd, config, url ?? undefined);
    ctx.existingFindings = [...findings];

    const agentResults = await runOrchestrator(ctx);
    const mergedFindings = lastSynthesis?.deduplicatedFindings ?? [
      ...findings,
      ...agentResults.flatMap((r) => r.findings),
    ];

    renderAIReport(agentResults, lastSynthesis);

    if (opts.file) {
      renderJsonReport(buildResult(cwd, startedAt, mergedFindings, { mode, url }), opts.file);
    }

    exitOnThreshold(opts, mergedFindings, config.thresholds.failOn);
    return;
  }

  // ── Standard output ────────────────────────────────────────────────────────
  const result = buildResult(cwd, startedAt, findings, { config: opts.config ?? "default", mode, url });
  const format = opts.output ?? config.output.format;

  if (format === "json") {
    renderJsonReport(result, opts.file);
  } else {
    renderConsoleReport(result);
    if (opts.file) renderJsonReport(result, opts.file);
  }

  exitOnThreshold(opts, findings, config.thresholds.failOn);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildResult(
  cwd: string,
  startedAt: Date,
  findings: Finding[],
  meta: Record<string, unknown>
): ScanResult {
  return {
    target: cwd,
    startedAt,
    completedAt: new Date(),
    findings,
    summary: makeSummary(findings),
    metadata: meta,
  };
}

function makeSummary(findings: Finding[]): ScanSummary {
  return {
    total: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
}

function exitOnThreshold(opts: ScanOptions, findings: Finding[], failOn: string): void {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const threshold = order[failOn] ?? 1;
  const failed = findings.some((f) => (order[f.severity] ?? 99) <= threshold);
  if (opts.ci && failed) process.exit(1);
}
