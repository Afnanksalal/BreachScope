import fs from "fs";
import path from "path";
import { logger } from "../../core/logger.js";
import { queryOSV, osvToFindings } from "../../apis/osv.js";
import type { Finding } from "../../core/types.js";

interface RubyGem { name: string; version?: string }

function parseGemfileLock(content: string): RubyGem[] {
  const gems: RubyGem[] = [];
  let inGemSection = false;

  for (const rawLine of content.split("\n")) {
    const line = rawLine;
    if (line.trim() === "GEM") { inGemSection = true; continue; }
    if (/^[A-Z]/.test(line.trim()) && line.trim() !== "GEM") { inGemSection = false; continue; }
    if (!inGemSection) continue;

    // Match "    gemname (1.2.3)" (4 spaces, gem name, version in parens)
    const m = line.match(/^    ([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)$/);
    if (m?.[1] && m?.[2]) {
      gems.push({ name: m[1], version: m[2] });
    }
  }

  return gems;
}

function parseGemfile(content: string): RubyGem[] {
  const gems: RubyGem[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith("gem ")) continue;
    const m = line.match(/gem\s+['"]([a-zA-Z0-9_\-]+)['"]/);
    if (m?.[1]) gems.push({ name: m[1] });
  }
  return gems;
}

export async function scanRuby(cwd: string): Promise<Finding[]> {
  const lockPath = path.join(cwd, "Gemfile.lock");
  const gemfilePath = path.join(cwd, "Gemfile");

  if (!fs.existsSync(lockPath) && !fs.existsSync(gemfilePath)) return [];

  let gems: RubyGem[] = [];
  try {
    if (fs.existsSync(lockPath)) {
      gems = parseGemfileLock(fs.readFileSync(lockPath, "utf-8"));
    } else {
      gems = parseGemfile(fs.readFileSync(gemfilePath, "utf-8"));
    }
  } catch { return []; }

  if (gems.length === 0) return [];
  logger.info(`  [ruby] Found ${gems.length} gem(s) to audit`);

  const findings: Finding[] = [];
  for (const gem of gems.slice(0, 60)) {
    const vulns = await queryOSV(gem.name, gem.version, "RubyGems");
    findings.push(...osvToFindings(vulns, gem.name));
  }
  return findings;
}
