import fs from "fs";
import path from "path";
import fg from "fast-glob";
import type { AgentContext, BreachScopeConfig } from "./types.js";
import { logger } from "./logger.js";

const SCAN_EXTENSIONS = ["ts", "tsx", "js", "jsx", "mjs", "py", "go", "rb", "php"];
const IGNORE_DIRS = ["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".turbo"];
const MAX_FILE_SIZE = 80 * 1024; // 80KB per file
const MAX_TOTAL_CHARS = 120_000; // keep total context manageable

export async function buildAgentContext(
  cwd: string,
  config: BreachScopeConfig,
  url?: string,
  scanMode?: string
): Promise<AgentContext> {
  logger.info("Building project context for AI agents...");

  // Read package.json
  let packageJson: Record<string, unknown> | undefined;
  const pkgPath = path.join(cwd, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      packageJson = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
    } catch {
      // ignore
    }
  }

  // Collect all dependencies
  const dependencies = [
    ...Object.keys((packageJson?.["dependencies"] as Record<string, string>) ?? {}),
    ...Object.keys((packageJson?.["devDependencies"] as Record<string, string>) ?? {}),
  ];

  // Collect source files with smart prioritization
  const pattern = `**/*.{${SCAN_EXTENSIONS.join(",")}}`;
  const allFiles = await fg(pattern, {
    cwd,
    ignore: IGNORE_DIRS.map((d) => `**/${d}/**`),
    absolute: true,
  });

  logger.debug(`Found ${allFiles.length} source files`);

  // Priority sort: auth, routes, config, api first
  const priority = (p: string) => {
    if (/auth|secret|token|cred/i.test(p)) return 0;
    if (/route|api|handler|middleware/i.test(p)) return 1;
    if (/config|env|setting/i.test(p)) return 2;
    if (/db|database|prisma|supabase/i.test(p)) return 3;
    return 10;
  };

  allFiles.sort((a, b) => priority(a) - priority(b));

  // Read files up to total char limit
  const files: Record<string, string> = {};
  let totalChars = 0;

  for (const filePath of allFiles) {
    if (totalChars >= MAX_TOTAL_CHARS) break;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;

      const content = fs.readFileSync(filePath, "utf-8");
      const rel = path.relative(cwd, filePath);
      files[rel] = content;
      totalChars += content.length;
    } catch {
      // skip unreadable files
    }
  }

  logger.info(`Context: ${Object.keys(files).length} files, ${dependencies.length} dependencies`);

  return {
    files,
    packageJson,
    dependencies,
    url,
    toolchain: config.toolchain,
    existingFindings: [],
    crawlCache: {},
    scanMode,
  };
}
