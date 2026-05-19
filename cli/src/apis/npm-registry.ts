import axios from "axios";
import { logger } from "../core/logger.js";
import type { NpmPackageMeta, Finding } from "../core/types.js";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week";

/**
 * Fetch package metadata and maintainer info from the npm registry.
 */
export async function fetchNpmMeta(packageName: string): Promise<NpmPackageMeta | null> {
  // Scoped packages: @scope/pkg → @scope%2Fpkg (encode slash only, not @)
  const encoded = packageName.startsWith("@")
    ? packageName.replace(/\//, "%2F")
    : encodeURIComponent(packageName);

  try {
    const [pkgRes, downloadsRes] = await Promise.allSettled([
      axios.get(`${NPM_REGISTRY}/${encoded}`, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { Accept: "application/json" },
      }),
      axios.get(`${NPM_DOWNLOADS}/${encoded}`, {
        timeout: 5000,
        validateStatus: () => true,
      }),
    ]);

    if (pkgRes.status !== "fulfilled" || pkgRes.value.status !== 200) return null;

    const raw = pkgRes.value.data as Record<string, unknown>;
    const latestVersion = raw["dist-tags"] as Record<string, string> | undefined;
    const latest = latestVersion?.["latest"] ?? "unknown";

    const versionData = (raw["versions"] as Record<string, Record<string, unknown>> | undefined)?.[latest] ?? {};
    const time = raw["time"] as Record<string, string> | undefined;

    const deps = (versionData["dependencies"] as Record<string, string>) ?? {};

    const weeklyDownloads =
      downloadsRes.status === "fulfilled" && downloadsRes.value.status === 200
        ? (downloadsRes.value.data as { downloads?: number }).downloads
        : undefined;

    return {
      name: String(raw["name"] ?? packageName),
      version: latest,
      description: String(raw["description"] ?? ""),
      maintainers: ((raw["maintainers"] ?? []) as Array<{ name: string; email: string }>),
      weeklyDownloads,
      publishedAt: time?.[latest],
      license: normalizeLicense(versionData["license"] ?? raw["license"]),
      deprecated: typeof versionData["deprecated"] === "string" ? versionData["deprecated"] : undefined,
      repository: String((versionData["repository"] as { url?: string } | undefined)?.url ?? ""),
      dependencies: deps,
    };
  } catch (e) {
    logger.debug(`[npm] Meta fetch failed for ${packageName}: ${e}`);
    return null;
  }
}

/**
 * Analyze npm metadata for supply chain risk signals.
 */
export function npmMetaToFindings(meta: NpmPackageMeta, toolName: string): Finding[] {
  const findings: Finding[] = [];

  // Single maintainer + very high downloads = high blast radius risk
  if (meta.maintainers.length === 1 && (meta.weeklyDownloads ?? 0) > 100_000) {
    findings.push({
      id: `npm-single-maintainer-${toolName}`,
      title: `${toolName} has a single maintainer with ${formatDownloads(meta.weeklyDownloads)} weekly downloads`,
      severity: "high",
      category: "supply-chain",
      tool: toolName,
      description: `A single maintainer controls a high-traffic package. If their npm account is compromised, a malicious version could propagate immediately to all downstream users.`,
      detail: `Maintainer: ${meta.maintainers[0]?.name} | Weekly downloads: ${formatDownloads(meta.weeklyDownloads)}`,
      remediation: "Pin the exact version in your lockfile. Enable Dependabot or Renovate to alert on unexpected version bumps. Consider auditing each update before deploying.",
      references: [`https://www.npmjs.com/package/${toolName}`],
    });
  }

  // Zero maintainers (abandoned)
  if (meta.maintainers.length === 0) {
    findings.push({
      id: `npm-no-maintainer-${toolName}`,
      title: `${toolName} has no registered maintainers (abandoned package)`,
      severity: "critical",
      category: "supply-chain",
      tool: toolName,
      description: "No maintainers are registered. This package may have been abandoned or its maintainers removed. Abandoned packages are prime targets for squatting attacks.",
      remediation: "Replace this dependency. Fork it if the functionality is critical.",
    });
  }

  // Published very recently (< 30 days) and in your production deps
  if (meta.publishedAt) {
    const daysSincePublish = (Date.now() - new Date(meta.publishedAt).getTime()) / 86400000;
    if (daysSincePublish < 30) {
      findings.push({
        id: `npm-recently-published-${toolName}`,
        title: `${toolName} was published ${Math.floor(daysSincePublish)} days ago`,
        severity: "medium",
        category: "supply-chain",
        tool: toolName,
        description: "Very recently published packages have had minimal community scrutiny. Malicious packages often try to get installed before the community can react.",
        remediation: "Verify the package author and inspect the source code before using in production.",
        references: [`https://www.npmjs.com/package/${toolName}`],
      });
    }
  }

  if (meta.deprecated) {
    findings.push({
      id: `npm-deprecated-${toolName}`,
      title: `${toolName} is deprecated on npm`,
      severity: "high",
      category: "supply-chain",
      tool: toolName,
      description: `The npm registry marks this package as deprecated: ${meta.deprecated}`,
      remediation: "Replace this dependency with the registry-recommended package or a maintained alternative.",
      references: [`https://www.npmjs.com/package/${toolName}`],
    });
  }

  if (meta.license && ["UNLICENSED", "UNKNOWN", "NOASSERTION"].includes(meta.license.toUpperCase())) {
    findings.push({
      id: `npm-risky-license-${toolName}`,
      title: `${toolName} has non-standard license metadata (${meta.license})`,
      severity: "low",
      category: "supply-chain",
      tool: toolName,
      description: "The package has missing, unknown, or unlicensed registry metadata. This can create legal and supply-chain review gaps for teams.",
      remediation: "Review the package repository and replace it if licensing cannot be confirmed.",
      references: [`https://www.npmjs.com/package/${toolName}`],
    });
  }

  return findings;
}

function normalizeLicense(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "object" && value !== null && "type" in value) {
    const type = (value as { type?: unknown }).type;
    return typeof type === "string" ? type : undefined;
  }
  return undefined;
}

function formatDownloads(n?: number): string {
  if (!n) return "unknown";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}
