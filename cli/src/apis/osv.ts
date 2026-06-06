import axios from "axios";
import { logger } from "../core/logger.js";
import type { OsvVulnerability, Finding, RelatedVulnerability, Severity } from "../core/types.js";

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

export interface OsvFindingOptions {
  packageVersion?: string;
  dependencyDepth?: number;
  dependencyScope?: Finding["dependencyScope"];
}

export function osvToFindings(
  vulns: OsvVulnerability[],
  toolName: string,
  options: OsvFindingOptions = {},
): Finding[] {
  const deduped = dedupeVulnerabilities(vulns);
  const groups = new Map<string, OsvVulnerability[]>();

  for (const vuln of deduped) {
    const fixedVersion = extractFixedVersion(vuln) ?? "unfixed";
    const key = `${toolName}|${fixedVersion}`;
    const group = groups.get(key) ?? [];
    group.push(vuln);
    groups.set(key, group);
  }

  return [...groups.values()].map((group) => {
    const sorted = [...group].sort((a, b) =>
      severityRank(mapVulnerabilitySeverity(b)) - severityRank(mapVulnerabilitySeverity(a))
    );
    const top = sorted[0]!;
    const severity = highestSeverity(sorted.map(mapVulnerabilitySeverity));
    const fixedVersion = extractFixedVersion(top);
    const related = sorted.map(toRelatedVulnerability);
    const cves = unique(related.flatMap((v) => v.aliases ?? []).filter((alias) => alias.startsWith("CVE-")));
    const osvIds = related.map((v) => v.id);
    const fixedVersions = unique(related.map((v) => v.fixedVersion).filter((v): v is string => Boolean(v)));
    const references = unique([
      ...related.map((v) => `https://osv.dev/vulnerability/${v.id}`),
      ...cves.map((cve) => `https://nvd.nist.gov/vuln/detail/${cve}`),
      ...related.flatMap((v) => v.references ?? []),
    ]);

    const title = related.length === 1
      ? `${toolName}: ${displayVulnerabilityId(related[0]!)} - ${top.summary}`
      : `${toolName}: ${related.length} vulnerable advisories (${displayVulnerabilityId(related[0]!)})`;

    return {
      id: `osv-${toolName}-${hashKey(osvIds.join("|"))}`,
      title,
      severity,
      category: "supply-chain" as const,
      tool: toolName,
      packageName: toolName,
      packageVersion: options.packageVersion,
      fixedVersion: fixedVersion ?? fixedVersions[0],
      dependencyDepth: options.dependencyDepth,
      dependencyScope: options.dependencyScope ?? "unknown",
      confidence: "medium",
      evidenceStrength: "moderate",
      signals: [
        "osv-version-match",
        related.length > 1 ? "grouped-advisories" : "single-advisory",
        fixedVersions.length > 0 ? "fix-available" : "no-fixed-version",
        ...(options.dependencyDepth === 0 ? ["direct-dependency"] : options.dependencyDepth !== undefined ? ["transitive-dependency"] : []),
      ],
      relatedVulnerabilities: related,
      description: related.length === 1
        ? top.summary
        : `${toolName} matched ${related.length} OSV advisories. The default report groups them by package and fix path to reduce duplicate CVE noise.`,
      detail: [
        `OSV IDs: ${osvIds.join(", ")}`,
        cves.length > 0 ? `CVEs: ${cves.join(", ")}` : null,
        fixedVersions.length > 0 ? `Fixed in: ${fixedVersions.join(", ")}` : null,
        `Latest advisory update: ${latestModified(sorted)}`,
      ].filter(Boolean).join(" | "),
      remediation: fixedVersions.length > 0
        ? `Update ${toolName} to ${fixedVersions[0]} or later.`
        : "Update to a non-vulnerable version when one is available. Check the advisory for vendor workarounds.",
      references,
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

function dedupeVulnerabilities(vulns: OsvVulnerability[]): OsvVulnerability[] {
  const seen = new Set<string>();
  const result: OsvVulnerability[] = [];
  for (const vuln of vulns) {
    const aliases = vuln.aliases?.join("|") ?? "";
    const key = [vuln.id, aliases].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(vuln);
  }
  return result;
}

function toRelatedVulnerability(v: OsvVulnerability): RelatedVulnerability {
  const severity = mapVulnerabilitySeverity(v);
  return {
    id: v.id,
    aliases: v.aliases,
    summary: v.summary,
    severity,
    fixedVersion: extractFixedVersion(v) ?? undefined,
    modified: v.modified,
    references: (v.references ?? [])
      .filter((r) => r.type === "FIX" || r.type === "WEB" || r.type === "ADVISORY")
      .map((r) => r.url),
  };
}

function mapVulnerabilitySeverity(v: OsvVulnerability): Severity {
  return mapOsvSeverity(v.severity, v.database_specific?.severity, v.ecosystem_specific?.severity);
}

function highestSeverity(severities: Severity[]): Severity {
  return severities.sort((a, b) => severityRank(b) - severityRank(a))[0] ?? "info";
}

function severityRank(severity: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

function displayVulnerabilityId(v: RelatedVulnerability): string {
  const cve = v.aliases?.find((alias) => alias.startsWith("CVE-"));
  return cve ? `${v.id} / ${cve}` : v.id;
}

function latestModified(vulns: OsvVulnerability[]): string {
  const sorted = [...vulns].map((v) => v.modified).filter(Boolean).sort();
  return sorted.at(-1) ?? "unknown";
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function hashKey(value: string): string {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
  }
  return Math.abs(hash).toString(36);
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
