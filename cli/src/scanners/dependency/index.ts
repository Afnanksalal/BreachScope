import path from "path";
import fs from "fs";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";
import { scanNpm } from "./npm.js";
import { scanLockfile } from "./lockfile.js";

export async function runDependencyScanner(cwd: string): Promise<Finding[]> {
  logger.section("Dependency / Supply Chain");
  const findings: Finding[] = [];

  const pkgPath = path.join(cwd, "package.json");
  const lockPath = path.join(cwd, "package-lock.json");
  const yarnPath = path.join(cwd, "yarn.lock");
  const pnpmPath = path.join(cwd, "pnpm-lock.yaml");

  if (fs.existsSync(pkgPath)) {
    findings.push(...await scanNpm(pkgPath));
  }

  if (fs.existsSync(lockPath)) {
    findings.push(...await scanLockfile(lockPath, "npm"));
  } else if (fs.existsSync(yarnPath)) {
    findings.push(...await scanLockfile(yarnPath, "yarn"));
  } else if (fs.existsSync(pnpmPath)) {
    findings.push(...await scanLockfile(pnpmPath, "pnpm"));
  }

  logger.info(`Found ${findings.length} dependency issue(s)`);
  return findings;
}
