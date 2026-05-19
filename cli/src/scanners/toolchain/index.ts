import { logger } from "../../core/logger.js";
import type { Finding, ToolchainConfig } from "../../core/types.js";
import { scanSupabase } from "./supabase.js";
import { scanVercel } from "./vercel.js";
import { scanGitHub } from "./github.js";

export async function runToolchainScanner(config: ToolchainConfig): Promise<Finding[]> {
  logger.section("Toolchain Breach Detection");
  const findings: Finding[] = [];

  const supabaseUrl = config.supabase?.url ?? process.env["SUPABASE_URL"];
  const supabaseKey = config.supabase?.anonKey ?? process.env["SUPABASE_ANON_KEY"];
  if (supabaseUrl && supabaseKey) {
    findings.push(...await scanSupabase(supabaseUrl, supabaseKey));
  } else {
    logger.debug("Supabase credentials not configured — skipping");
  }

  const vercelToken = config.vercel?.token ?? process.env["VERCEL_TOKEN"];
  if (vercelToken) {
    findings.push(...await scanVercel(vercelToken, config.vercel?.projectId));
  } else {
    logger.debug("Vercel token not configured — skipping");
  }

  const githubToken = config.github?.token ?? process.env["GITHUB_TOKEN"];
  const githubRepo = config.github?.repo ?? process.env["GITHUB_REPO"];
  if (githubToken) {
    findings.push(...await scanGitHub(githubToken, githubRepo));
  } else {
    logger.debug("GitHub token not configured — skipping");
  }

  logger.info(`Found ${findings.length} toolchain issue(s)`);
  return findings;
}
