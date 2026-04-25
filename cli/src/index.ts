#!/usr/bin/env node
import { Command } from "commander";
import { runScan } from "./commands/scan.js";
import { generateConfig } from "./core/config.js";
import { logger } from "./core/logger.js";
import { makeLoginCommand, makeLogoutCommand, makeWhoamiCommand } from "./commands/login.js";
import path from "path";
import fs from "fs";

const program = new Command();

program
  .name("breachscope")
  .description("Supply chain & toolchain breach scanner — audit your entire stack")
  .version("0.1.0");

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
  .option("--ai", "enable AI multi-agent analysis (requires OPENAI_API_KEY + FIRECRAWL_API_KEY)")
  .option("--browser", "launch authenticated browser probe — logs in and runs passive security checks (requires --url and --ai)")
  .option("--breach", "focus on CVE, supply chain, and SaaS incident intelligence")
  .option("--bug", "focus on code audit, static analysis, and vulnerability testing")
  .option("-v, --verbose", "verbose debug output")
  .action(async (opts) => {
    if (opts.breach) opts.scanMode = "breach";
    else if (opts.bug) opts.scanMode = "bug";
    else opts.scanMode = "all";
    await runScan(opts);
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
  .option("-v, --verbose")
  .action(async (url: string, opts) => {
    await runScan({ ...opts, target: "blackbox", mode: "basic", url });
  });

// ─── smoke ────────────────────────────────────────────────────────────────────
program
  .command("smoke <url>")
  .description("Smoke tests against a live URL — reachability, error leakage, auth bypass")
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
  .option("--ai", "enable AI synthesis (requires OPENAI_API_KEY)")
  .option("-v, --verbose")
  .action(async (opts) => {
    await runScan({ ...opts, target: "all" });
  });

// ─── auth ─────────────────────────────────────────────────────────────────────
program.addCommand(makeLoginCommand());
program.addCommand(makeLogoutCommand());
program.addCommand(makeWhoamiCommand());

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
