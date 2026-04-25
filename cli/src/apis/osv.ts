import axios from "axios";
import { logger } from "../core/logger.js";
import type { OsvVulnerability, Finding } from "../core/types.js";

const OSV_API = "https://api.osv.dev/v1";

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

interface OsvBatchQuery {
  queries: OsvQuery[];
}

export async function queryOSV(
  packageName: string,
  version?: string,
  ecosystem = "npm"
): Promise<OsvVulnerability[]> {
  try {
    const body: OsvQuery = {
      package: { name: packageName, ecosystem },
      ...(version ? { version } : {}),
    };

    const res = await axios.post<{ vulns?: OsvVulnerability[] }>(`${OSV_API}/query`, body, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { "Content-Type": "application/json" },
    });

    if (res.status !== 200 || !Array.isArray(res.data?.vulns)) return [];
    return res.data.vulns;
  } catch (e) {
    logger.debug(`[osv] Query failed for ${packageName}: ${e}`);
    return [];
  }
}

export async function queryOSVBatch(
  packages: Array<{ name: string; version?: string; ecosystem?: string }>
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();
  if (packages.length === 0) return results;

  const CHUNK = 100; // OSV batch limit per request

  for (let i = 0; i < packages.length; i += CHUNK) {
    const chunk = packages.slice(i, i + CHUNK);

    try {
      const body: OsvBatchQuery = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem ?? "npm" },
          ...(p.version ? { version: p.version } : {}),
        })),
      };

      const res = await axios.post<{
        results?: Array<{ vulns?: OsvVulnerability[]; next_page_token?: string }>;
      }>(`${OSV_API}/querybatch`, body, {
        timeout: 20000,
        validateStatus: () => true,
        headers: { "Content-Type": "application/json" },
      });

      if (res.status !== 200 || !Array.isArray(res.data?.results)) continue;

      for (let j = 0; j < chunk.length; j++) {
        const pkg = chunk[j]!;
        results.set(pkg.name, res.data.results[j]?.vulns ?? []);
      }
    } catch (e) {
      logger.debug(`[osv] Batch query failed: ${e}`);
    }
  }

  return results;
}

export function osvToFindings(vulns: OsvVulnerability[], toolName: string): Finding[] {
  return vulns.map((v) => {
    const severity  = mapOsvSeverity(v.severity, v.database_specific?.severity, v.ecosystem_specific?.severity);
    const cveAlias  = v.aliases?.find((a) => a.startsWith("CVE-"));
    const fixedVer  = extractFixedVersion(v);
    const idLabel   = cveAlias ? `${v.id} (${cveAlias})` : v.id;

    return {
      id:          `osv-${v.id}-${toolName}`,
      title:       `${toolName}: ${idLabel} — ${v.summary}`,
      severity,
      category:    "supply-chain" as const,
      tool:        toolName,
      description: v.summary,
      detail:      [
        `OSV ID: ${v.id}`,
        cveAlias ? `CVE: ${cveAlias}` : null,
        fixedVer  ? `Fixed in: ${fixedVer}` : null,
        `Modified: ${v.modified}`,
      ].filter(Boolean).join(" | "),
      remediation: fixedVer
        ? `Update ${toolName} to ${fixedVer} or later.`
        : "Update to a non-vulnerable version. Check the advisory for patched versions.",
      references: [
        `https://osv.dev/vulnerability/${v.id}`,
        cveAlias ? `https://nvd.nist.gov/vuln/detail/${cveAlias}` : null,
        ...v.references.filter((r) => r.type === "FIX" || r.type === "WEB").map((r) => r.url),
      ].filter((r): r is string => r !== null),
    };
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractFixedVersion(v: OsvVulnerability): string | null {
  for (const affected of v.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type === "SEMVER" || range.type === "ECOSYSTEM") {
        for (const event of range.events ?? []) {
          if (event.fixed) return event.fixed;
        }
      }
    }
  }
  return null;
}

function mapOsvSeverity(
  severity?: Array<{ type: string; score: string }> | string,
  dbSeverity?: string,
  ecosystemSeverity?: string
): Finding["severity"] {
  // database_specific and ecosystem_specific are plain strings like "HIGH"
  for (const plain of [dbSeverity, ecosystemSeverity]) {
    if (!plain) continue;
    const s = plain.toUpperCase();
    if (s === "CRITICAL")                      return "critical";
    if (s === "HIGH")                          return "high";
    if (s === "MEDIUM" || s === "MODERATE")    return "medium";
    if (s === "LOW")                           return "low";
  }

  // OSV top-level severity is an array of CVSS objects: { type: "CVSS_V3", score: "7.5" }
  if (Array.isArray(severity)) {
    // Prefer CVSS_V4, then CVSS_V3, then CVSS_V2
    const ordered = [...severity].sort((a, b) => {
      const rank = (t: string) => t.includes("V4") ? 0 : t.includes("V3") ? 1 : 2;
      return rank(a.type) - rank(b.type);
    });

    for (const entry of ordered) {
      // CVSS score can be a plain numeric string "7.5" or a full vector string
      const num = parseFloat(entry.score);
      if (!isNaN(num)) {
        if (num >= 9.0) return "critical";
        if (num >= 7.0) return "high";
        if (num >= 4.0) return "medium";
        if (num > 0)    return "low";
      }
    }
    return "info";
  }

  // Older OSV records that returned severity as a plain string
  if (typeof severity === "string") {
    const s = severity.toUpperCase();
    if (s === "CRITICAL")                    return "critical";
    if (s === "HIGH")                        return "high";
    if (s === "MEDIUM" || s === "MODERATE")  return "medium";
    if (s === "LOW")                         return "low";
  }

  return "info";
}
