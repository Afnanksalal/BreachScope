import ora from "ora";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import { loadConfig } from "../core/config.js";
import { logger } from "../core/logger.js";
import { fetchRemoteConfig, syncRemoteConfig } from "../core/remote-config.js";
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
import { runAttackProbe } from "../agents/attack-probe.js";
import { pushScanToDashboard } from "../core/push-scan.js";
import type { SubchainScanResult } from "../core/types.js";

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
  let target = opts.target ?? "all";
  let mode   = opts.mode   ?? "basic";
  const url = opts.url;

  if (opts.verbose) logger.setVerbose(true);

  // Always fetch remote config — apply dashboard defaults when no local flags set,
  // and pull API keys for AI mode
  const remote = await fetchRemoteConfig();
  if (remote) {
    if (!opts.mode)   mode   = remote.defaultMode   as typeof mode;
    if (!opts.target) target = remote.defaultScanMode as typeof target;
    if (opts.ai) {
      if (!process.env.OPENAI_API_KEY    && remote.openaiKey)    process.env.OPENAI_API_KEY    = remote.openaiKey;
      if (!process.env.FIRECRAWL_API_KEY && remote.firecrawlKey) process.env.FIRECRAWL_API_KEY = remote.firecrawlKey;
    }
  }

  console.log(chalk.dim(BANNER));
  const scanMode = opts.scanMode ?? "all";
  const scanModeLabel = scanMode === "full"
    ? chalk.red("B") + chalk.yellow("U") + chalk.magenta("G") + chalk.red("+") + chalk.red("BREACH") + chalk.gray(" (everything — max coverage)")
    : scanMode === "breach"
    ? chalk.red("BREACH") + chalk.gray(" (CVE · supply chain · credential hunt)")
    : scanMode === "bug"
    ? chalk.yellow("BUG") + chalk.gray(" (static analysis · injection · code vulns)")
    : chalk.white("ALL");

  console.log(chalk.gray(`  Mode: ${chalk.white(mode.toUpperCase())}  │  Target: ${chalk.white(target.toUpperCase())}  │  Scan: ${scanModeLabel}${url ? `  │  URL: ${chalk.white(url)}` : ""}`));
  logger.blank();

  const findings: Finding[] = [];

  // Probe activity log — sent to dashboard for the Probe Activity tab
  const probeServices: Array<{
    id: string; name: string; category: string;
    steps: string[]; findingsCount: number; tokensUsed: number;
  }> = [];
  let probeAttack: { url: string; attacks: string[]; pagesVisited: string[]; findingsCount: number; tokensUsed: number } | undefined;

  // ── Static scanners ───────────────────────────────────────────────────────
  // breach mode: deps + toolchain + supply chain; skip code quality patterns
  // bug mode: deep code audit + deps for known-vuln versions; skip toolchain/subchain
  // all mode: everything
  //
  // When target="all" and no local project is detected (URL-only run), skip static
  // scanners automatically. Explicit --target flags always run regardless.

  const PROJECT_MANIFESTS = ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "Gemfile", "pyproject.toml"];
  const isProjectDir = PROJECT_MANIFESTS.some((m) => fs.existsSync(path.join(cwd, m)));

  const isFull = scanMode === "full";
  const runDeps      = target === "dependency" || (target === "all" && isProjectDir);
  const runCode      = target === "code"       || (target === "all" && isProjectDir);
  const runToolchain = (target === "toolchain" || (target === "all" && isProjectDir)) && (isFull || scanMode !== "bug");

  if (runDeps) {
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

  if (runCode) {
    const spinner = ora(
      scanMode === "full"   ? "Full code audit — bug patterns + breach patterns + credentials..." :
      scanMode === "bug"    ? "Deep code audit (bug-finding mode)..." :
      scanMode === "breach" ? "Scanning for credentials & breach indicators..." :
      "Auditing source code..."
    ).start();
    try {
      const result = await runCodeAudit(cwd, scanMode);
      findings.push(...result);
      spinner.succeed(`Code audit — ${result.length} issue(s)`);
    } catch (e) {
      spinner.fail("Code audit failed");
      logger.debug(e);
    }
  }

  if (runToolchain) {
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

  // ── Sub-toolchain scan (skipped in bug mode — not supply chain focused) ──────
  let subchainResult: SubchainScanResult | null = null;
  const shouldRunSubchain = (target === "dependency" || (target === "all" && isProjectDir)) && (isFull || scanMode !== "bug");
  if (shouldRunSubchain) {
    try {
      subchainResult = await runSubchainScan(cwd, mode, config.subchain);
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
          probeServices.push({
            id: def.id, name: def.name, category: def.category,
            steps: result.steps, findingsCount: result.findings.length, tokensUsed: result.tokensUsed,
          });
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

  // ── Active attack probe (authenticated browser pentest) ───────────────────
  if (opts.browser && opts.url && process.stdin.isTTY) {
    logger.blank();
    logger.section("Active Penetration Test");
    console.log(chalk.gray("  Launches a real browser, logs in, then actively probes for: SQLi, XSS,"));
    console.log(chalk.gray("  JWT attacks, IDOR, CORS misconfig, rate limiting, sensitive paths, and more.\n"));
    const { promptText: pt, promptSecret: ps } = await import("../core/interactive.js");
    const loginUrl = await pt(`  Login page URL (leave blank to use ${opts.url}): `);
    const username = await pt("  Username / email: ");
    const password = await ps("  Password: ");

    if (!username || !password) {
      console.log(chalk.yellow("  Skipping — username and password are required."));
    } else {
      const spinner = ora("Launching attack probe — this may take a few minutes...").start();
      try {
        const result = await runAttackProbe(opts.url, {
          username,
          password,
          loginUrl: loginUrl || opts.url,
        });
        findings.push(...result.findings);
        probeAttack = {
          url: opts.url, attacks: result.attacksSummary,
          pagesVisited: result.pagesVisited, findingsCount: result.findings.length, tokensUsed: result.tokensUsed,
        };
        spinner.succeed(
          `Attack probe — ${result.findings.length} finding(s) across ${result.pagesVisited.length} page(s) (${result.tokensUsed.toLocaleString()} tokens)`
        );
        if (result.attacksSummary.length > 0) {
          console.log(chalk.gray(`  Attacks run: ${result.attacksSummary.slice(0, 6).join("  │  ")}`));
        }
        if (result.pagesVisited.length > 0) {
          console.log(chalk.gray(`  Pages visited: ${result.pagesVisited.slice(0, 5).join(", ")}`));
        }
      } catch (e) {
        spinner.fail(`Attack probe failed: ${String(e)}`);
        logger.debug(e);
      }
    }
  }

  // ── AI multi-agent layer ───────────────────────────────────────────────────
  if (opts.ai) {
    logger.section("AI Multi-Agent Analysis");
    const ctx = await buildAgentContext(cwd, config, url ?? undefined, scanMode);
    ctx.existingFindings = [...findings];

    const agentResults = await runOrchestrator(ctx);

    // AI agents may discover findings not caught by static scanners.
    // Merge them in, but never let GPT's curation shrink the raw findings set.
    const staticTitles = new Set(findings.map((f) => f.title));
    const aiNewFindings = agentResults
      .filter((r) => r.agent !== "report")
      .flatMap((r) => r.findings)
      .filter((af) => !staticTitles.has(af.title));
    const mergedFindings = [...findings, ...aiNewFindings];

    renderAIReport(agentResults, lastSynthesis, mergedFindings);

    const aiResult = buildResult(cwd, startedAt, mergedFindings, { mode, url });

    if (opts.file) {
      renderJsonReport(aiResult, opts.file);
    }

    await pushScan(aiResult, { mode, scanMode, url, explicitFlags: !!(opts.mode || opts.target), subchainResult, probeServices, probeAttack, aiReport: lastSynthesis ? JSON.stringify(lastSynthesis) : undefined });

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

  await pushScan(result, { mode, scanMode, url, explicitFlags: !!(opts.mode || opts.target), subchainResult, probeServices, probeAttack });

  exitOnThreshold(opts, findings, config.thresholds.failOn);
}

async function pushScan(
  result: ScanResult,
  opts: {
    mode: string; scanMode: string; url?: string; explicitFlags?: boolean;
    subchainResult?: SubchainScanResult | null;
    probeServices?: Array<{ id: string; name: string; category: string; steps: string[]; findingsCount: number; tokensUsed: number }>;
    probeAttack?: { url: string; attacks: string[]; pagesVisited: string[]; findingsCount: number; tokensUsed: number };
    aiReport?: string;
  }
): Promise<void> {
  const spinner = ora("Uploading results to dashboard…").start();

  // Build compact tool risk data for the dashboard
  const toolRiskData = opts.subchainResult?.toolResults.map((r) => ({
    name:            r.tool.name,
    kind:            r.tool.kind,
    depth:           r.tool.depth,
    parent:          r.tool.parent,
    riskScore:       r.riskScore,
    aiSummary:       r.aiSummary,
    osvCount:        r.osvVulnerabilities.length,
    osvIds:          r.osvVulnerabilities.map((v) => v.id).slice(0, 10),
    scorecardScore:  r.scorecard?.score,
    weeklyDownloads: r.npmMeta?.weeklyDownloads,
    maintainerCount: r.npmMeta?.maintainers.length,
    findingsCount:   r.findings.length,
    github:          r.tool.github ? `https://github.com/${r.tool.github}` : undefined,
    version:         r.tool.version,
  })) ?? undefined;

  const probeData = (opts.probeServices?.length || opts.probeAttack)
    ? { services: opts.probeServices ?? [], attack: opts.probeAttack }
    : undefined;

  const [scanId] = await Promise.all([
    pushScanToDashboard(result, {
      mode:         opts.mode,
      scanMode:     opts.scanMode,
      url:          opts.url,
      toolsScanned: opts.subchainResult?.toolsScanned ?? result.findings.reduce((acc, f) => {
        return f.tool && !acc.tools.has(f.tool)
          ? { count: acc.count + 1, tools: new Set([...acc.tools, f.tool]) }
          : acc;
      }, { count: 0, tools: new Set<string>() }).count,
      toolRiskData,
      probeData,
      aiReport: opts.aiReport,
    }),
    // Sync mode settings back to dashboard if user passed explicit flags
    opts.explicitFlags ? syncRemoteConfig(opts.mode, opts.scanMode ?? "all") : Promise.resolve(),
  ]);

  if (scanId) {
    spinner.succeed(`Saved to dashboard — view at ${chalk.white(`https://breachscoope.vercel.app/dashboard/scan/${scanId}`)}`);
  } else {
    spinner.stop();
  }
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
