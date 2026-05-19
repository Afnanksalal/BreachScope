import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";
import { queryOSVBatch, osvToFindings } from "../../apis/osv.js";
import { discoverBom } from "../../reporters/sbom.js";

const OSV_ECOSYSTEMS: Record<string, string> = {
  composer: "Packagist",
  maven: "Maven",
  nuget: "NuGet",
  hex: "Hex",
  pub: "Pub",
};

export async function scanAdditionalEcosystems(cwd: string): Promise<Finding[]> {
  const bom = discoverBom(cwd);
  const packages = bom.components
    .filter((component) => OSV_ECOSYSTEMS[component.ecosystem])
    .map((component) => ({
      name: component.name,
      version: cleanVersion(component.version),
      ecosystem: OSV_ECOSYSTEMS[component.ecosystem],
    }));

  if (packages.length === 0) return [];

  logger.info(`  [multi] Found ${packages.length} package(s) across Java/PHP/.NET/Elixir/Dart ecosystems`);

  const results = await queryOSVBatch(packages);
  const findings: Finding[] = [];
  for (const pkg of packages) {
    findings.push(...osvToFindings(results.get(pkg.name) ?? [], pkg.name));
  }
  return findings;
}

function cleanVersion(version?: string): string | undefined {
  if (!version) return undefined;
  const cleaned = version.replace(/^[~^<>=!\s]+/, "").trim();
  return cleaned && !cleaned.includes("*") ? cleaned : undefined;
}
