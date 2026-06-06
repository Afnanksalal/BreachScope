#!/usr/bin/env node
import { Command } from "commander";
import { runScan } from "./commands/scan.js";
import { runSandbox } from "./commands/sandbox.js";
import { generateConfig } from "./core/config.js";
import { logger } from "./core/logger.js";
import { makeLoginCommand, makeLogoutCommand, makeWhoamiCommand } from "./commands/login.js";
import { makeInitCiCommand } from "./commands/ci.js";
import { makeRuntimeCommand } from "./commands/runtime.js";
import { renderSbom, type SbomFormat } from "./reporters/sbom.js";
import { renderVexFromScanFile } from "./reporters/vex.js";
import { renderFixSuggestionsFromScanFile } from "./reporters/fix-suggestions.js";
import path from "path";
import fs from "fs";

const program = new Command();

program
  .name("breachscope")
  .description("Supply chain & toolchain breach scanner — audit your entire stack")
  .version("0.3.0");

// ─── scan ─────────────────────────────────────────────────────────────────────
program
  .command("scan")
  .description("Run a full breach scan on the current project")
  .option(
    "-m, --mode <mode>",
    "scan depth: basic (direct tools) | major (+sub-deps) | deep (full transitive tree)",
    "basic"
  )
  .option("-t, --target <target>", "scope: all | dependency | toolchain | code | blackbox | smoke", "all")
  .option("-u, --url <url>", "target URL for blackbox/smoke scanning")
  .option("-o, --output <format>", "output format: console | json | sarif", "console")
  .option("-f, --file <path>", "write output to a file")
  .option("-c, --config <path>", "path to breachscope.yaml config file")
  .option("--ci", "exit code 1 if findings exceed severity threshold (for CI pipelines)")
  .option("--fail-on <severity>", "override CI threshold: critical | high | medium | low | info")
  .option("--baseline <path>", "compare findings against a BreachScope baseline file")
  .option("--write-baseline <path>", "write current findings to a baseline file")
  .option("--new-findings-only", "with --baseline, report and fail only on new findings")
  .option("--policy <path>", "path to policy-as-code YAML/JSON file")
  .option("--show-noise", "include hidden/review findings in the report")
  .option("--all-cves", "include CVE advisories that are hidden by default")
  .option("--llm-triage", "use the configured LLM to reason over borderline findings")
  .option("--breach", "focus on CVE, supply chain, and SaaS incident intelligence")
  .option("--bug", "focus on code audit, static analysis, and vulnerability testing")
  .option("--no-upload", "keep results local even when dashboard credentials are configured")
  .option("-v, --verbose", "verbose debug output")
  .action(async (opts, command) => {
    if (command.getOptionValueSource("mode") === "default") delete opts.mode;
    if (command.getOptionValueSource("target") === "default") delete opts.target;
    if (opts.breach && opts.bug) opts.scanMode = "full";
    else if (opts.breach) opts.scanMode = "breach";
    else if (opts.bug) opts.scanMode = "bug";
    else opts.scanMode = "all";
    await runScan(opts);
  });

program
  .command("sbom")
  .description("Generate an SBOM from supported manifests and lockfiles")
  .option("-o, --output <format>", "SBOM format: cyclonedx | spdx", "cyclonedx")
  .option("-f, --file <path>", "write SBOM to a file")
  .action((opts) => {
    const format = opts.output === "spdx" ? "spdx" : "cyclonedx";
    renderSbom(process.cwd(), format as SbomFormat, opts.file);
  });

program
  .command("vex")
  .description("Generate an OpenVEX document from a BreachScope JSON scan result")
  .requiredOption("--from <path>", "BreachScope JSON scan result")
  .option("-f, --file <path>", "write OpenVEX JSON to a file")
  .action((opts) => {
    renderVexFromScanFile(opts.from, opts.file);
  });

program
  .command("suggest-fixes")
  .description("Generate prioritized fix suggestions from a BreachScope JSON scan result")
  .requiredOption("--from <path>", "BreachScope JSON scan result")
  .option("-f, --file <path>", "write Markdown suggestions to a file")
  .action((opts) => {
    renderFixSuggestionsFromScanFile(opts.from, opts.file);
  });

// ─── audit ────────────────────────────────────────────────────────────────────
program
  .command("audit")
  .description("Static code audit only")
  .option("-o, --output <format>", "output format: console | json", "console")
  .option("-f, --file <path>", "write output to file")
  .option("-v, --verbose")
  .action(async (opts) => {
    await runScan({ ...opts, target: "code", mode: "basic" });
  });

// ─── probe ────────────────────────────────────────────────────────────────────
program
  .command("probe <url>")
  .description("Blackbox security probe against a live URL")
  .option("-o, --output <format>", "output format: console | json", "console")
  .option("--show-noise", "include hidden/review probe findings in the report")
  .option("--llm-triage", "use the configured LLM to reason over borderline probe findings")
  .option("-v, --verbose")
  .action(async (url: string, opts) => {
    await runScan({ ...opts, target: "blackbox", mode: "basic", url });
  });

// ─── smoke ────────────────────────────────────────────────────────────────────
program
  .command("smoke <url>")
  .description("Smoke tests against a live URL — reachability, error leakage, auth bypass")
  .option("--show-noise", "include hidden/review smoke findings in the report")
  .option("--llm-triage", "use the configured LLM to reason over borderline smoke findings")
  .option("-v, --verbose")
  .action(async (url: string, opts) => {
    await runScan({ ...opts, target: "smoke", mode: "basic", url });
  });

// ─── deps ─────────────────────────────────────────────────────────────────────
program
  .command("deps")
  .description("Dependency and lockfile supply chain scan")
  .option("-m, --mode <mode>", "scan depth: basic | major | deep", "basic")
  .option("-o, --output <format>", "output format: console | json", "console")
  .option("--show-noise", "include hidden/review dependency findings in the report")
  .option("--all-cves", "include CVE advisories that are hidden by default")
  .option("--llm-triage", "use the configured LLM to reason over borderline dependency findings")
  .option("-v, --verbose")
  .action(async (opts) => {
    await runScan({ ...opts, target: "dependency" });
  });

// ─── toolchain ────────────────────────────────────────────────────────────────
program
  .command("toolchain")
  .description("Detect and audit every tool in the codebase — OSS + SaaS pipelines")
  .option("-m, --mode <mode>", "scan depth: basic | major | deep", "basic")
  .option("-o, --output <format>", "output format: console | json", "console")
  .option("--show-noise", "include hidden/review toolchain findings in the report")
  .option("--all-cves", "include CVE advisories that are hidden by default")
  .option("--llm-triage", "use the configured LLM to reason over borderline toolchain findings")
  .option("-v, --verbose")
  .action(async (opts) => {
    await runScan({ ...opts, target: "toolchain" });
  });

// ─── sandbox ─────────────────────────────────────────────────────────────────
program
  .command("sandbox")
  .description("Spin up a Docker sandbox, run the app inside it, and attack it with server-side techniques: env secrets, internal ports, command injection, SSTI, path traversal, prototype pollution, SSRF, JWT attacks")
  .option("-p, --port <number>", "app port inside the container (auto-detected from project)", parseInt)
  .option("-i, --image <name>", "custom base Docker image to use (default: auto-detected)")
  .option("-t, --timeout <seconds>", "max seconds to wait for the app to start (default: 60)", parseInt)
  .option("--deep", "run extended attack sequences (120 iterations instead of 80)")
  .option("--breach", "focus companion agents on supply chain & credential risk")
  .option("--bug", "focus companion agents on exploitable code vulnerabilities")
  .option("--scan-mode <mode>", "companion agent focus: all | breach | bug | full (overrides --breach/--bug)")
  .option("--include-secrets", "allow sandbox AI and Docker context to include .env files and local secrets")
  .option("--ci", "set exit code 1 when sandbox finds critical or high findings")
  .option("--no-cleanup", "keep the container running after the scan (for manual inspection)")
  .option("--no-upload", "keep sandbox results local even when dashboard credentials are configured")
  .option("-u, --url <url>", "target URL context (for dashboard reporting)")
  .option("-o, --output <format>", "output format: console | json", "console")
  .option("-f, --file <path>", "write results to a file")
  .option("-v, --verbose", "verbose debug output")
  .action(async (opts) => {
    if (opts.scanMode && ["all", "breach", "bug", "full"].includes(opts.scanMode)) {
      // explicit --scan-mode wins
    } else if (opts.breach && opts.bug) {
      opts.scanMode = "full";
    } else if (opts.breach) {
      opts.scanMode = "breach";
    } else if (opts.bug) {
      opts.scanMode = "bug";
    }
    await runSandbox(opts);
  });

// ─── auth ─────────────────────────────────────────────────────────────────────
program.addCommand(makeLoginCommand());
program.addCommand(makeLogoutCommand());
program.addCommand(makeWhoamiCommand());
program.addCommand(makeInitCiCommand());
program.addCommand(makeRuntimeCommand());

// ─── init ─────────────────────────────────────────────────────────────────────
program
  .command("init")
  .description("Create a breachscope.yaml config file")
  .option("--force", "overwrite existing config")
  .action((opts) => {
    const dest = path.join(process.cwd(), "breachscope.yaml");
    if (fs.existsSync(dest) && !opts.force) {
      logger.warn("breachscope.yaml already exists. Use --force to overwrite.");
      return;
    }
    generateConfig(dest);
    logger.success("Created breachscope.yaml");
  });

program.parseAsync(process.argv);
