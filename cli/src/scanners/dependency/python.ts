import fs from "fs";
import path from "path";
import axios from "axios";
import { logger } from "../../core/logger.js";
import { queryOSV, osvToFindings } from "../../apis/osv.js";
import type { Finding } from "../../core/types.js";

interface PythonPackage { name: string; version?: string }

// ─── Parsers ──────────────────────────────────────────────────────────────────

function parseRequirementsTxt(content: string): PythonPackage[] {
  const pkgs: PythonPackage[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-") || line.startsWith("http")) continue;
    // Strip extras: "flask[async]==2.0.1" → "flask", "2.0.1"
    const withoutExtras = line.replace(/\[.*?\]/, "");
    const m = withoutExtras.match(/^([A-Za-z0-9_.\-]+)\s*(?:[=~^<>!]=?\s*([^\s,;]+))?/);
    if (m?.[1]) {
      pkgs.push({ name: m[1].toLowerCase().replace(/_/g, "-"), version: m[2] });
    }
  }
  return pkgs;
}

function parsePyprojectToml(content: string): PythonPackage[] {
  const pkgs: PythonPackage[] = [];

  // PEP 621: [project] dependencies = ["requests>=2.28", ...]
  const pep621Match = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (pep621Match?.[1]) {
    for (const dep of pep621Match[1].matchAll(/"([^"]+)"/g)) {
      const raw = dep[1] ?? "";
      const m = raw.match(/^([A-Za-z0-9_.\-]+)/);
      if (m?.[1]) pkgs.push({ name: m[1].toLowerCase().replace(/_/g, "-") });
    }
  }

  // Poetry: [tool.poetry.dependencies]
  const poetryMatch = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\[|$)/);
  if (poetryMatch?.[1]) {
    for (const line of poetryMatch[1].split("\n")) {
      const m = line.match(/^([a-zA-Z][A-Za-z0-9_.\-]*)\s*=\s*"?([^"\n]+)"?/);
      if (m?.[1] && m[1].toLowerCase() !== "python") {
        pkgs.push({ name: m[1].toLowerCase().replace(/_/g, "-"), version: m[2]?.replace(/[\^~>=<]/, "") });
      }
    }
  }

  // uv / rye: [tool.uv.dependencies] or [dependency-groups]
  const uvMatch = content.match(/\[tool\.uv\.dependencies\]([\s\S]*?)(?=\[|$)/);
  if (uvMatch?.[1]) {
    for (const dep of uvMatch[1].matchAll(/"([^"]+)"/g)) {
      const raw = dep[1] ?? "";
      const m = raw.match(/^([A-Za-z0-9_.\-]+)/);
      if (m?.[1]) pkgs.push({ name: m[1].toLowerCase().replace(/_/g, "-") });
    }
  }

  return pkgs;
}

function parsePipfile(content: string): PythonPackage[] {
  const pkgs: PythonPackage[] = [];
  const packagesMatch = content.match(/\[packages\]([\s\S]*?)(?=\[|$)/);
  if (!packagesMatch?.[1]) return pkgs;
  for (const line of packagesMatch[1].split("\n")) {
    const m = line.match(/^([A-Za-z0-9_.\-]+)\s*=/);
    if (m?.[1]) pkgs.push({ name: m[1].toLowerCase().replace(/_/g, "-") });
  }
  return pkgs;
}

function parseSetupPy(content: string): PythonPackage[] {
  const pkgs: PythonPackage[] = [];
  // install_requires=[...] or install_requires = [...]
  const m = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (!m?.[1]) return pkgs;
  for (const dep of m[1].matchAll(/['"]([A-Za-z0-9_.\-][^'"]*)['"]/g)) {
    const name = (dep[1] ?? "").match(/^([A-Za-z0-9_.\-]+)/)?.[1];
    if (name) pkgs.push({ name: name.toLowerCase().replace(/_/g, "-") });
  }
  return pkgs;
}

// ─── OSV batch scan ───────────────────────────────────────────────────────────

async function osvScanPython(pkgs: PythonPackage[]): Promise<Finding[]> {
  if (pkgs.length === 0) return [];

  // Batch query OSV with PyPI ecosystem
  try {
    const body = {
      queries: pkgs.map((p) => ({
        package: { name: p.name, ecosystem: "PyPI" },
        ...(p.version ? { version: p.version } : {}),
      })),
    };

    const res = await axios.post<{
      results?: Array<{ vulns?: import("../../core/types.js").OsvVulnerability[] }>;
    }>("https://api.osv.dev/v1/querybatch", body, {
      timeout: 20000,
      validateStatus: () => true,
      headers: { "Content-Type": "application/json" },
    });

    if (res.status !== 200 || !Array.isArray(res.data?.results)) return [];

    const findings: Finding[] = [];
    for (let i = 0; i < pkgs.length; i++) {
      const vulns = res.data.results[i]?.vulns ?? [];
      if (vulns.length > 0) {
        const pkg = pkgs[i]!;
        findings.push(...osvToFindings(vulns, pkg.name, { packageVersion: pkg.version, dependencyDepth: 0, dependencyScope: "unknown" }));
      }
    }
    return findings;
  } catch (e) {
    logger.debug(`[python] OSV batch failed: ${e}`);
    // Fallback: individual queries for first 20
    const findings: Finding[] = [];
    for (const pkg of pkgs.slice(0, 20)) {
      const vulns = await queryOSV(pkg.name, pkg.version, "PyPI");
      findings.push(...osvToFindings(vulns, pkg.name, { packageVersion: pkg.version, dependencyDepth: 0, dependencyScope: "unknown" }));
    }
    return findings;
  }
}

// ─── Main export ─────────────────────────────────────────────────────────────

export async function scanPython(cwd: string): Promise<Finding[]> {
  const pkgs: PythonPackage[] = [];
  const seen = new Set<string>();
  const add = (p: PythonPackage) => { if (!seen.has(p.name)) { seen.add(p.name); pkgs.push(p); } };

  const tryParse = (file: string, parser: (c: string) => PythonPackage[]) => {
    const filePath = path.join(cwd, file);
    if (!fs.existsSync(filePath)) return;
    try { parser(fs.readFileSync(filePath, "utf-8")).forEach(add); } catch { /* skip */ }
  };

  tryParse("requirements.txt",      parseRequirementsTxt);
  tryParse("requirements-dev.txt",  parseRequirementsTxt);
  tryParse("requirements/base.txt", parseRequirementsTxt);
  tryParse("requirements/prod.txt", parseRequirementsTxt);
  tryParse("pyproject.toml",        parsePyprojectToml);
  tryParse("Pipfile",               parsePipfile);
  tryParse("setup.py",              parseSetupPy);

  if (pkgs.length === 0) return [];
  logger.info(`  [python] Found ${pkgs.length} package(s) to audit`);

  return osvScanPython(pkgs);
}

// Export parsers for use by the detector
export { parseRequirementsTxt, parsePyprojectToml, parsePipfile, parseSetupPy };
export type { PythonPackage };
