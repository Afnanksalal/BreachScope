import fs from "fs";
import path from "path";
import fg from "fast-glob";
import type { AgentContext, BreachScopeConfig, LanguageDep } from "./types.js";
import { logger } from "./logger.js";

const SCAN_EXTENSIONS = ["ts", "tsx", "js", "jsx", "mjs", "py", "go", "rb", "php", "java", "cs", "rs", "ex", "exs", "dart"];
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
    followSymbolicLinks: false,
    suppressErrors: true,
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

  const allDeps = detectAllDeps(cwd, packageJson);
  logger.info(`Context: ${Object.keys(files).length} files, ${allDeps.length} deps across ${new Set(allDeps.map((d) => d.ecosystem)).size} ecosystem(s)`);

  return {
    files,
    packageJson,
    dependencies,
    allDeps,
    url,
    toolchain: config.toolchain,
    existingFindings: [],
    crawlCache: {},
    scanMode,
  };
}

export function detectAllDepsForContext(cwd: string, packageJson: Record<string, unknown> | undefined): LanguageDep[] {
  return detectAllDeps(cwd, packageJson);
}

function detectAllDeps(cwd: string, packageJson: Record<string, unknown> | undefined): LanguageDep[] {
  const deps: LanguageDep[] = [];
  const read = (p: string) => { try { return fs.readFileSync(p, "utf-8"); } catch { return null; } };

  // npm
  const npmDeps = {
    ...((packageJson?.["dependencies"] as Record<string, string>) ?? {}),
    ...((packageJson?.["devDependencies"] as Record<string, string>) ?? {}),
  };
  for (const [name, version] of Object.entries(npmDeps)) {
    deps.push({ name, version: String(version), ecosystem: "npm" });
  }

  // Python — requirements.txt
  const reqs = read(path.join(cwd, "requirements.txt"));
  if (reqs) {
    for (const line of reqs.split("\n")) {
      const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*([=><!][=<>]?\s*[\d.*,]+)?/);
      if (m?.[1] && !line.startsWith("#")) deps.push({ name: m[1], version: m[2]?.trim(), ecosystem: "PyPI" });
    }
  }
  // pyproject.toml — basic
  const pyproject = read(path.join(cwd, "pyproject.toml"));
  if (pyproject) {
    for (const m of pyproject.matchAll(/["']([A-Za-z0-9_.-]+)\s*(>=|==|~=)[^"'\n,]+["']/g)) {
      if (m[1]) deps.push({ name: m[1], ecosystem: "PyPI" });
    }
  }
  // Pipfile
  const pipfile = read(path.join(cwd, "Pipfile"));
  if (pipfile) {
    for (const m of pipfile.matchAll(/^([a-z][a-z0-9_.-]*)\s*=/gim)) {
      if (m[1] && m[1] !== "python_version" && m[1] !== "url") deps.push({ name: m[1], ecosystem: "PyPI" });
    }
  }

  // Go — go.mod
  const gomod = read(path.join(cwd, "go.mod"));
  if (gomod) {
    for (const m of gomod.matchAll(/^\s*([a-z][^\s]+)\s+v([^\s]+)/gm)) {
      if (m[1] && !m[1].startsWith("//")) deps.push({ name: m[1], version: m[2], ecosystem: "Go" });
    }
  }

  // Rust — Cargo.toml
  const cargo = read(path.join(cwd, "Cargo.toml"));
  if (cargo) {
    for (const m of cargo.matchAll(/^([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]+)"|[\{][^}]*version\s*=\s*"([^"]+)")/gm)) {
      if (m[1]) deps.push({ name: m[1], version: m[2] ?? m[3], ecosystem: "crates.io" });
    }
  }

  // Ruby — Gemfile
  const gemfile = read(path.join(cwd, "Gemfile"));
  if (gemfile) {
    for (const m of gemfile.matchAll(/gem\s+['"]([^'"]+)['"]/g)) {
      if (m[1]) deps.push({ name: m[1], ecosystem: "RubyGems" });
    }
  }

  // PHP — composer.json
  const composer = read(path.join(cwd, "composer.json"));
  if (composer) {
    try {
      const c = JSON.parse(composer) as { require?: Record<string, string>; "require-dev"?: Record<string, string> };
      for (const [name, version] of Object.entries({ ...c.require, ...c["require-dev"] })) {
        if (!name.startsWith("php") && !name.startsWith("ext-")) deps.push({ name, version, ecosystem: "Packagist" });
      }
    } catch { /* ignore */ }
  }

  // Elixir — mix.exs
  const mix = read(path.join(cwd, "mix.exs"));
  if (mix) {
    for (const m of mix.matchAll(/\{:([a-z_]+),\s*"~>\s*([^"]+)"/g)) {
      if (m[1]) deps.push({ name: m[1], version: m[2], ecosystem: "Hex" });
    }
  }

  // Dart — pubspec.yaml
  const pubspec = read(path.join(cwd, "pubspec.yaml"));
  if (pubspec) {
    let inDeps = false;
    for (const line of pubspec.split("\n")) {
      if (/^(dependencies|dev_dependencies):/.test(line)) { inDeps = true; continue; }
      if (inDeps && /^\S/.test(line) && !line.startsWith(" ")) { inDeps = false; }
      if (inDeps) {
        const m = line.match(/^\s{2}([a-z][a-z0-9_]*)\s*:/);
        if (m?.[1] && m[1] !== "sdk") deps.push({ name: m[1], ecosystem: "pub" });
      }
    }
  }

  // Deduplicate by name+ecosystem
  const seen = new Set<string>();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
