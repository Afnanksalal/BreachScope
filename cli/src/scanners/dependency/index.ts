import path from "path";
import fs from "fs";
import chalk from "chalk";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";
import { scanNpm } from "./npm.js";
import { scanLockfile } from "./lockfile.js";
import { scanPython } from "./python.js";
import { scanGo } from "./go.js";
import { scanRust } from "./rust.js";
import { scanRuby } from "./ruby.js";
import { scanAdditionalEcosystems } from "./multilang.js";

interface LangScan { lang: string; detected: boolean; findings: Finding[] }

export async function runDependencyScanner(cwd: string): Promise<Finding[]> {
  logger.section("Dependency / Supply Chain");

  const exists = (f: string) => fs.existsSync(path.join(cwd, f));

  // Detect which languages are present
  const hasJs      = exists("package.json");
  const hasPython  = exists("requirements.txt") || exists("pyproject.toml") || exists("Pipfile") || exists("setup.py");
  const hasGo      = exists("go.mod");
  const hasRust    = exists("Cargo.toml") || exists("Cargo.lock");
  const hasRuby    = exists("Gemfile") || exists("Gemfile.lock");
  const hasJava    = exists("pom.xml") || exists("build.gradle") || exists("build.gradle.kts");
  const hasPhp     = exists("composer.json") || exists("composer.lock");
  const hasDotnet  = fs.readdirSync(cwd).some((file) => file.endsWith(".csproj")) || exists("packages.lock.json");
  const hasElixir  = exists("mix.exs") || exists("mix.lock");
  const hasDart    = exists("pubspec.yaml") || exists("pubspec.lock");

  const detected = [
    hasJs     && chalk.yellow("JS/npm"),
    hasPython && chalk.blue("Python"),
    hasGo     && chalk.cyan("Go"),
    hasRust   && chalk.red("Rust"),
    hasRuby   && chalk.magenta("Ruby"),
    hasJava   && chalk.red("Java"),
    hasPhp    && chalk.blue("PHP"),
    hasDotnet && chalk.green(".NET"),
    hasElixir && chalk.magenta("Elixir"),
    hasDart   && chalk.cyan("Dart"),
  ].filter(Boolean);

  if (detected.length > 0) {
    logger.info(`  Detected language(s): ${detected.join(", ")}`);
  }

  const scans: LangScan[] = [];

  // ── JavaScript / npm ────────────────────────────────────────────────────────
  if (hasJs) {
    const pkgPath  = path.join(cwd, "package.json");
    const lockPath = path.join(cwd, "package-lock.json");
    const yarnPath = path.join(cwd, "yarn.lock");
    const pnpmPath = path.join(cwd, "pnpm-lock.yaml");

    const jsFindings: Finding[] = [];
    jsFindings.push(...await scanNpm(pkgPath));
    if (exists("package-lock.json"))  jsFindings.push(...await scanLockfile(lockPath, "npm"));
    else if (exists("yarn.lock"))     jsFindings.push(...await scanLockfile(yarnPath, "yarn"));
    else if (exists("pnpm-lock.yaml")) jsFindings.push(...await scanLockfile(pnpmPath, "pnpm"));
    scans.push({ lang: "JS/npm", detected: true, findings: jsFindings });
  }

  // ── Python ───────────────────────────────────────────────────────────────────
  if (hasPython) {
    const pyFindings = await scanPython(cwd);
    scans.push({ lang: "Python", detected: true, findings: pyFindings });
  }

  // ── Go ───────────────────────────────────────────────────────────────────────
  if (hasGo) {
    const goFindings = await scanGo(cwd);
    scans.push({ lang: "Go", detected: true, findings: goFindings });
  }

  // ── Rust ─────────────────────────────────────────────────────────────────────
  if (hasRust) {
    const rustFindings = await scanRust(cwd);
    scans.push({ lang: "Rust", detected: true, findings: rustFindings });
  }

  // ── Ruby ─────────────────────────────────────────────────────────────────────
  if (hasRuby) {
    const rubyFindings = await scanRuby(cwd);
    scans.push({ lang: "Ruby", detected: true, findings: rubyFindings });
  }

  if (hasJava || hasPhp || hasDotnet || hasElixir || hasDart) {
    const multiFindings = await scanAdditionalEcosystems(cwd);
    scans.push({ lang: "Java/PHP/.NET/Elixir/Dart", detected: true, findings: multiFindings });
  }

  const findings = scans.flatMap((s) => s.findings);

  // Per-language summary
  for (const s of scans) {
    if (s.findings.length > 0) {
      logger.info(`  [${s.lang}] ${s.findings.length} issue(s)`);
    }
  }

  if (scans.length === 0) {
    logger.info("  No supported package manifest found");
  }

  logger.info(`Found ${findings.length} dependency issue(s)`);
  return findings;
}
