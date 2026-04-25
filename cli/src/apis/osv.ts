import axios from "axios";
import { logger } from "../core/logger.js";
import type { OsvVulnerability, Finding } from "../core/types.js";

const OSV_API = "https://api.osv.dev/v1";

interface OsvQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

interface OsvBatchQuery {
  queries: OsvQuery[];
}

/**
 * Query OSV.dev for vulnerabilities affecting a package.
 * Uses the batch endpoint to minimize round trips.
 */
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

    const res = await axios.post(`${OSV_API}/query`, body, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { "Content-Type": "application/json" },
    });

    if (res.status !== 200 || !Array.isArray(res.data?.vulns)) return [];

    return res.data.vulns as OsvVulnerability[];
  } catch (e) {
    logger.debug(`[osv] Query failed for ${packageName}: ${e}`);
    return [];
  }
}

/**
 * Batch query OSV for multiple packages at once.
 */
export async function queryOSVBatch(
  packages: Array<{ name: string; version?: string; ecosystem?: string }>
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();
  if (packages.length === 0) return results;

  const CHUNK = 100; // OSV batch limit

  for (let i = 0; i < packages.length; i += CHUNK) {
    const chunk = packages.slice(i, i + CHUNK);

    try {
      const body: OsvBatchQuery = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem ?? "npm" },
          ...(p.version ? { version: p.version } : {}),
        })),
      };

      const res = await axios.post(`${OSV_API}/querybatch`, body, {
        timeout: 15000,
        validateStatus: () => true,
      });

      if (res.status !== 200 || !Array.isArray(res.data?.results)) continue;

      const rawResults = res.data.results as Array<{ vulns?: OsvVulnerability[] }>;
      for (let j = 0; j < chunk.length; j++) {
        const pkg = chunk[j]!;
        const vulns = rawResults[j]?.vulns ?? [];
        results.set(pkg.name, vulns);
      }
    } catch (e) {
      logger.debug(`[osv] Batch query failed: ${e}`);
    }
  }

  return results;
}

/**
 * Convert OSV vulnerabilities into BreachScope findings.
 */
export function osvToFindings(vulns: OsvVulnerability[], toolName: string): Finding[] {
  return vulns.map((v) => {
    const severity = mapOsvSeverity(v.severity);
    return {
      id: `osv-${v.id}-${toolName}`,
      title: `${toolName}: ${v.id} — ${v.summary}`,
      severity,
      category: "supply-chain" as const,
      tool: toolName,
      description: v.summary,
      detail: `OSV ID: ${v.id} | Modified: ${v.modified}`,
      remediation: "Update to a non-vulnerable version. Check the advisory for patched versions.",
      references: [
        `https://osv.dev/vulnerability/${v.id}`,
        ...v.references.filter((r) => r.type === "FIX").map((r) => r.url),
      ],
    };
  });
}

function mapOsvSeverity(severity?: string): Finding["severity"] {
  const s = (severity ?? "").toUpperCase();
  if (s === "CRITICAL") return "critical";
  if (s === "HIGH") return "high";
  if (s === "MEDIUM" || s === "MODERATE") return "medium";
  if (s === "LOW") return "low";
  return "info";
}
