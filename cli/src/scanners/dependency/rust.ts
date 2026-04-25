import fs from "fs";
import path from "path";
import { logger } from "../../core/logger.js";
import { queryOSV, osvToFindings } from "../../apis/osv.js";
import type { Finding } from "../../core/types.js";

interface RustCrate { name: string; version?: string }

// ─── Cargo.toml parser ────────────────────────────────────────────────────────
function parseCargoToml(content: string): RustCrate[] {
  const crates: RustCrate[] = [];
  let inDeps = false;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (/^\[(?:dependencies|dev-dependencies|build-dependencies)\]/.test(line)) {
      inDeps = true; continue;
    }
    if (line.startsWith("[") && !line.startsWith("[dependencies")) {
      inDeps = false; continue;
    }
    if (!inDeps || !line || line.startsWith("#")) continue;

    // name = "1.0.0"
    const simple = line.match(/^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"/);
    if (simple?.[1]) { crates.push({ name: simple[1], version: simple[2]?.replace(/^[~^>=<]+/, "") }); continue; }

    // name = { version = "1.0", ... }
    const inline = line.match(/^([a-zA-Z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/);
    if (inline?.[1]) { crates.push({ name: inline[1], version: inline[2]?.replace(/^[~^>=<]+/, "") }); }
  }

  return crates;
}

// ─── Cargo.lock parser (more precise versions) ───────────────────────────────
function parseCargoLock(content: string): RustCrate[] {
  const crates: RustCrate[] = [];
  let currentName: string | undefined;
  let currentVersion: string | undefined;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line === "[[package]]") {
      if (currentName) crates.push({ name: currentName, version: currentVersion });
      currentName = undefined; currentVersion = undefined; continue;
    }
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch?.[1]) { currentName = nameMatch[1]; continue; }
    const verMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (verMatch?.[1]) { currentVersion = verMatch[1]; }
  }
  if (currentName) crates.push({ name: currentName, version: currentVersion });

  // Deduplicate by name (keep first occurrence)
  const seen = new Set<string>();
  return crates.filter((c) => { const ok = !seen.has(c.name); seen.add(c.name); return ok; });
}

export async function scanRust(cwd: string): Promise<Finding[]> {
  const lockPath = path.join(cwd, "Cargo.lock");
  const tomlPath = path.join(cwd, "Cargo.toml");

  if (!fs.existsSync(tomlPath) && !fs.existsSync(lockPath)) return [];

  let crates: RustCrate[] = [];
  try {
    if (fs.existsSync(lockPath)) {
      crates = parseCargoLock(fs.readFileSync(lockPath, "utf-8"));
    } else {
      crates = parseCargoToml(fs.readFileSync(tomlPath, "utf-8"));
    }
  } catch { return []; }

  if (crates.length === 0) return [];
  logger.info(`  [rust] Found ${crates.length} crate(s) to audit`);

  const findings: Finding[] = [];
  for (const crate of crates.slice(0, 80)) {
    const vulns = await queryOSV(crate.name, crate.version, "crates.io");
    findings.push(...osvToFindings(vulns, crate.name));
  }
  return findings;
}

export { parseCargoToml, parseCargoLock };
export type { RustCrate };
