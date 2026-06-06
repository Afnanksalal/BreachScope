import fs from "fs";
import path from "path";
import { logger } from "../../core/logger.js";
import { queryOSV, osvToFindings } from "../../apis/osv.js";
import type { Finding } from "../../core/types.js";

interface GoModule { name: string; version?: string }

function parseGoMod(content: string): GoModule[] {
  const mods: GoModule[] = [];
  let inRequire = false;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line === "require (") { inRequire = true; continue; }
    if (line === ")") { inRequire = false; continue; }

    if (inRequire || line.startsWith("require ")) {
      const inner = line.startsWith("require ") ? line.slice(8) : line;
      const m = inner.trim().match(/^([^\s]+)\s+v([^\s]+)/);
      if (m?.[1] && !m[1].startsWith("//")) {
        mods.push({ name: m[1], version: m[2] });
      }
    }
  }
  return mods;
}

export async function scanGo(cwd: string): Promise<Finding[]> {
  const modPath = path.join(cwd, "go.mod");
  if (!fs.existsSync(modPath)) return [];

  let content: string;
  try { content = fs.readFileSync(modPath, "utf-8"); } catch { return []; }

  const mods = parseGoMod(content);
  if (mods.length === 0) return [];
  logger.info(`  [go] Found ${mods.length} module(s) to audit`);

  const findings: Finding[] = [];
  // Query OSV in batches of 20 (Go modules can be many)
  for (const mod of mods.slice(0, 50)) {
    const vulns = await queryOSV(mod.name, mod.version, "Go");
    findings.push(...osvToFindings(vulns, mod.name, { packageVersion: mod.version, dependencyDepth: 0, dependencyScope: "production" }));
  }
  return findings;
}

export { parseGoMod };
export type { GoModule };
