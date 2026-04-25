import axios from "axios";
import { logger } from "../core/logger.js";
import type { DepsDevProject, Finding } from "../core/types.js";

const DEPS_DEV = "https://api.deps.dev/v3";

/**
 * Fetch project security metadata from deps.dev by GitHub slug.
 * @param githubSlug "org/repo"
 */
export async function fetchDepsDevProject(githubSlug: string): Promise<DepsDevProject | null> {
  const encoded = encodeURIComponent(`github.com/${githubSlug}`);

  try {
    const res = await axios.get(`${DEPS_DEV}/projects/${encoded}`, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { Accept: "application/json" },
    });

    if (res.status !== 200 || !res.data) return null;

    return res.data as DepsDevProject;
  } catch (e) {
    logger.debug(`[deps.dev] Failed for ${githubSlug}: ${e}`);
    return null;
  }
}

/**
 * Fetch the dependency list of an npm package version from deps.dev.
 * Used for sub-dep traversal in major/deep mode.
 */
export async function fetchPackageDependencies(
  packageName: string,
  version: string,
  ecosystem = "npm"
): Promise<Array<{ name: string; version: string }>> {
  const pkgEncoded = encodeURIComponent(packageName);

  try {
    const res = await axios.get(
      `${DEPS_DEV}/systems/${ecosystem}/packages/${pkgEncoded}/versions/${encodeURIComponent(version)}:dependencies`,
      {
        timeout: 10000,
        validateStatus: () => true,
      }
    );

    if (res.status !== 200 || !res.data?.nodes) return [];

    return (res.data.nodes as Array<{ versionKey?: { name: string; version: string } }>)
      .filter((n): n is { versionKey: { name: string; version: string } } => !!n.versionKey)
      .map((n) => ({ name: n.versionKey.name, version: n.versionKey.version }));
  } catch (e) {
    logger.debug(`[deps.dev] Dependency fetch failed for ${packageName}@${version}: ${e}`);
    return [];
  }
}

/**
 * Resolve the latest stable version of an npm package via deps.dev.
 */
export async function resolveLatestVersion(packageName: string): Promise<string | null> {
  const encoded = encodeURIComponent(packageName);

  try {
    const res = await axios.get(`${DEPS_DEV}/systems/npm/packages/${encoded}`, {
      timeout: 8000,
      validateStatus: () => true,
    });

    if (res.status !== 200) return null;

    const versions = res.data?.versions as Array<{ versionKey: { version: string }; isDefault?: boolean }>;
    const defaultVersion = versions?.find((v) => v.isDefault);
    return defaultVersion?.versionKey.version ?? null;
  } catch {
    return null;
  }
}

/**
 * Convert deps.dev data into findings.
 */
export function depsDevToFindings(project: DepsDevProject, toolName: string, githubSlug: string): Finding[] {
  const findings: Finding[] = [];
  const scorecardScore = project.scorecardV2?.score?.overall ?? project.scorecard?.score;

  if (scorecardScore !== undefined && scorecardScore < 4) {
    findings.push({
      id: `depsdev-score-${toolName}`,
      title: `${toolName} has a low deps.dev security score (${scorecardScore.toFixed(1)})`,
      severity: "high",
      category: "supply-chain",
      tool: toolName,
      description: `deps.dev reports a security score of ${scorecardScore.toFixed(1)} for github.com/${githubSlug}. This indicates poor security hygiene in the project.`,
      remediation: "Review the project's security posture on deps.dev before trusting it.",
      references: [`https://deps.dev/project/github/${encodeURIComponent(`github.com/${githubSlug}`)}`],
    });
  }

  return findings;
}
