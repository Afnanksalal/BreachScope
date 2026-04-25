import axios from "axios";
import { logger } from "../core/logger.js";

export interface PypiMeta {
  name: string;
  version: string;
  summary: string;
  repository?: string;
  dependencies: Record<string, string>;
  publishedAt?: string;
  maintainers: string[];
  weeklyDownloads?: number;
}

/**
 * Fetch package metadata from PyPI JSON API.
 */
export async function fetchPypiMeta(packageName: string): Promise<PypiMeta | null> {
  try {
    const res = await axios.get<{
      info: {
        name: string; version: string; summary?: string; author?: string;
        project_urls?: Record<string, string>;
        requires_dist?: string[];
      };
      releases?: Record<string, Array<{ upload_time?: string }>>;
    }>(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`, {
      timeout: 10000,
      validateStatus: () => true,
    });

    if (res.status !== 200) return null;

    const info = res.data.info;

    // Find GitHub URL from project_urls
    const repository = Object.values(info.project_urls ?? {}).find(
      (u): u is string => typeof u === "string" && u.includes("github.com")
    );

    // Parse requires_dist into a dependency map
    // Format: "requests (>=2.20.0)", "numpy>=1.20; python_version>='3.7'"
    const dependencies: Record<string, string> = {};
    for (const req of info.requires_dist ?? []) {
      const normalized = req.split(";")[0]!.trim(); // drop environment markers
      const m = normalized.match(/^([A-Za-z0-9_.\-]+)\s*(?:\(?([^)]*)\)?)?/);
      if (m?.[1]) {
        const depName = m[1].toLowerCase().replace(/_/g, "-");
        dependencies[depName] = m[2]?.trim() ?? "*";
      }
    }

    const releaseFiles = res.data.releases?.[info.version] ?? [];
    const publishedAt = releaseFiles[0]?.upload_time;

    // Try pypistats for download count
    let weeklyDownloads: number | undefined;
    try {
      const statsRes = await axios.get<{ data: { last_week: number } }>(
        `https://pypistats.org/api/packages/${encodeURIComponent(packageName)}/recent?period=week`,
        { timeout: 5000, validateStatus: () => true }
      );
      if (statsRes.status === 200) weeklyDownloads = statsRes.data?.data?.last_week;
    } catch { /* optional */ }

    return {
      name: info.name,
      version: info.version,
      summary: info.summary ?? "",
      repository,
      dependencies,
      publishedAt,
      maintainers: info.author ? [info.author] : [],
      weeklyDownloads,
    };
  } catch (e) {
    logger.debug(`[pypi] Meta fetch failed for ${packageName}: ${e}`);
    return null;
  }
}

/**
 * Supply-chain risk analysis for PyPI packages (mirrors npmMetaToFindings).
 */
export function pypiMetaToFindings(meta: PypiMeta, toolName: string) {
  const findings: Array<{
    id: string; title: string; severity: "critical" | "high" | "medium" | "low";
    category: "supply-chain"; tool: string; description: string; remediation: string; references: string[];
  }> = [];

  if (meta.maintainers.length === 0) {
    findings.push({
      id: `pypi-no-maintainer-${toolName}`,
      title: `${toolName} has no registered maintainers (abandoned)`,
      severity: "critical",
      category: "supply-chain",
      tool: toolName,
      description: "No maintainers are registered. This PyPI package may be abandoned or its maintainers removed.",
      remediation: "Replace this dependency or fork it if the functionality is critical.",
      references: [`https://pypi.org/project/${toolName}/`],
    });
  }

  if (meta.publishedAt) {
    const days = (Date.now() - new Date(meta.publishedAt).getTime()) / 86400000;
    if (days < 30) {
      findings.push({
        id: `pypi-recently-published-${toolName}`,
        title: `${toolName} was published ${Math.floor(days)} day(s) ago`,
        severity: "medium",
        category: "supply-chain",
        tool: toolName,
        description: "Very recently published packages have minimal community scrutiny. Malicious packages often get installed before the community reacts.",
        remediation: "Verify the package author and inspect the source code before using in production.",
        references: [`https://pypi.org/project/${toolName}/`],
      });
    }
  }

  return findings;
}
