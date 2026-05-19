import axios from "axios";
import pLimit from "p-limit";
import { logger } from "../core/logger.js";
import type { DetectedTool, ToolPipelineResult, Finding, ScanMode } from "../core/types.js";
import { fetchScorecard, scorecardToFindings } from "../apis/scorecard.js";
import { queryOSV, osvToFindings } from "../apis/osv.js";
import { fetchDepsDevProject, depsDevToFindings } from "../apis/deps-dev.js";
import { fetchNpmMeta, npmMetaToFindings } from "../apis/npm-registry.js";
import { fetchPypiMeta, pypiMetaToFindings } from "../apis/pypi.js";
import { complete } from "../core/ai.js";
import { scoreSupplyChainRisk, type SupplyChainRiskScore } from "../core/supply-chain-risk.js";

const OSS_ANALYSIS_SYSTEM = `You are a senior supply-chain security analyst reviewing an open-source package.
Given structured security data about a package, produce a concise risk assessment.

Return JSON:
{
  "riskScore": 0-100,
  "summary": "2-3 sentence risk assessment",
  "keyRisks": ["risk1", "risk2", ...],
  "recommendation": "use | use-with-caution | replace | urgent-replace"
}

riskScore guide: 0=no risk, 25=minor concerns, 50=notable risks, 75=serious risks, 100=critical/avoid.
No markdown fences.`;

const limit = pLimit(5);

// Extract GitHub slug from npm repository field
function extractGithubSlug(repoUrl?: string): string | undefined {
  if (!repoUrl) return undefined;
  const m = repoUrl.match(/github\.com[/:]([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?]|$)/);
  return m?.[1];
}

/**
 * Dangerous patterns in lifecycle scripts (preinstall/postinstall/install).
 * Runs on the actual package source from GitHub.
 */
const DANGEROUS_SCRIPT_PATTERNS = [
  /curl\s+\S+\s*\|\s*(ba)?sh/i,
  /wget\s+\S+\s*\|\s*(ba)?sh/i,
  /eval\s*\(/,
  /base64\s+(-d|--decode)/,
  /node\s+-e\s+/,
  /python[23]?\s+-c\s+/,
  /child_process/i,
  /require\(['"]child_process['"]\)/,
];

/**
 * Dangerous patterns in source code.
 */
const SOURCE_CODE_PATTERNS: Array<{ pattern: RegExp; title: string; severity: Finding["severity"] }> = [
  {
    pattern: /eval\s*\(\s*(?:Buffer\.from|atob)\s*\(/i,
    title: "Obfuscated eval() detected",
    severity: "critical",
  },
  {
    pattern: /require\(['"]child_process['"]\)[\s\S]{0,150}(?:exec|spawn)\s*\(/i,
    title: "Dynamic child_process exec in source",
    severity: "high",
  },
  {
    pattern: /(?:^|[^a-zA-Z])fetch\s*\(\s*['"`]https?:\/\/(?!(?:registry\.npmjs\.org|github\.com|raw\.githubusercontent\.com))/im,
    title: "Unexpected network call to external host",
    severity: "medium",
  },
  {
    pattern: /process\.env\.[A-Z_]{5,}[\s\S]{0,100}(?:fetch|http|axios\.)/i,
    title: "Env var exfiltration pattern",
    severity: "high",
  },
];

/**
 * Audit lifecycle scripts and sample source code from GitHub for a package.
 * Only runs when the GitHub repo is known (for major/deep modes).
 */
async function crawlPackageSource(
  packageName: string,
  github: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const rawBase = `https://raw.githubusercontent.com/${github}/HEAD`;

  // ── Install script audit ─────────────────────────────────────────────────
  try {
    const pkgRes = await axios.get(`${rawBase}/package.json`, {
      timeout: 8000,
      validateStatus: () => true,
    });

    if (pkgRes.status === 200 && pkgRes.data && typeof pkgRes.data === "object") {
      const pkg = pkgRes.data as Record<string, unknown>;
      const scripts = (pkg["scripts"] ?? {}) as Record<string, string>;
      const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare"];

      for (const scriptName of LIFECYCLE) {
        const cmd = scripts[scriptName];
        if (!cmd) continue;
        for (const pattern of DANGEROUS_SCRIPT_PATTERNS) {
          if (pattern.test(cmd)) {
            findings.push({
              id: `source-script-${packageName}-${scriptName}`,
              title: `${packageName}: Suspicious "${scriptName}" lifecycle script`,
              severity: "high",
              category: "supply-chain",
              tool: packageName,
              description: `The "${scriptName}" script in the package's GitHub source contains patterns commonly used in supply chain attacks (e.g., remote code fetch+execute).`,
              detail: cmd.slice(0, 300),
              remediation: "Pin to a specific version and inspect each upgrade. Consider `npm config set ignore-scripts true` for CI environments.",
              references: [
                `https://github.com/${github}/blob/HEAD/package.json`,
                `https://www.npmjs.com/package/${packageName}`,
              ],
            });
            break;
          }
        }
      }
    }
  } catch {
    // Network failures are expected — continue
  }

  // ── Source code pattern scan ─────────────────────────────────────────────
  const ENTRY_CANDIDATES = ["index.js", "src/index.js", "lib/index.js"];
  for (const entry of ENTRY_CANDIDATES) {
    try {
      const res = await axios.get(`${rawBase}/${entry}`, {
        timeout: 6000,
        validateStatus: () => true,
      });

      if (res.status !== 200 || typeof res.data !== "string") continue;

      const src = res.data.slice(0, 12000); // first 12KB

      for (const { pattern, title, severity } of SOURCE_CODE_PATTERNS) {
        if (pattern.test(src)) {
          findings.push({
            id: `source-code-${packageName}-${title.toLowerCase().replace(/[^a-z0-9]/g, "-")}`,
            title: `${packageName}: ${title}`,
            severity,
            category: "supply-chain",
            tool: packageName,
            description: `Source code analysis of \`${packageName}\` (${entry}) detected a suspicious pattern that may indicate malicious behavior.`,
            remediation: "Inspect the source manually before using in production. Consider an alternative package.",
            references: [
              `https://github.com/${github}/blob/HEAD/${entry}`,
              `https://www.npmjs.com/package/${packageName}`,
            ],
          });
        }
      }
      break; // Stop after first found entry
    } catch {
      // Continue to next candidate
    }
  }

  return findings;
}

/**
 * Run the full OSS security pipeline for a detected tool.
 * Works even without a known GitHub repo (OSV + npm queries don't require it).
 * For major/deep modes, also crawls package source code from GitHub.
 */
export async function runOssPipeline(
  tool: DetectedTool,
  mode: ScanMode = "basic"
): Promise<ToolPipelineResult> {
  logger.info(`[oss] Scanning ${tool.name}`);

  const findings: Finding[] = [];

  const ecosystem = tool.ecosystem ?? "npm";

  // OSV works for all ecosystems — use the correct one
  const osvVulns = await limit(() => queryOSV(tool.name, tool.version, ecosystem));

  // Registry metadata — use the right registry per ecosystem
  let npmMeta: import("../core/types.js").NpmPackageMeta | undefined;
  let pypiMeta: import("../apis/pypi.js").PypiMeta | undefined;
  let registryGithub: string | undefined;

  if (ecosystem === "PyPI") {
    pypiMeta = await limit(() => fetchPypiMeta(tool.name)).then((m) => m ?? undefined);
    registryGithub = pypiMeta?.repository
      ? extractGithubSlug(pypiMeta.repository)
      : undefined;
  } else if (ecosystem === "npm") {
    const meta = await limit(() => fetchNpmMeta(tool.name));
    npmMeta = meta ?? undefined;
    registryGithub = extractGithubSlug(npmMeta?.repository);
  } else if (ecosystem === "Go") {
    // Infer GitHub from module path (github.com/org/repo)
    const m = tool.name.match(/^github\.com\/([^/]+\/[^/]+)/);
    if (m?.[1]) registryGithub = m[1];
  }
  // crates.io, RubyGems: rely on toolmap github field only

  // Resolve GitHub slug: toolmap > registry > inferred
  const github: string | undefined = tool.github ?? registryGithub;

  let scorecard = null;
  let depsDevData = null;

  if (github) {
    [scorecard, depsDevData] = await Promise.all([
      limit(() => fetchScorecard(github)),
      limit(() => fetchDepsDevProject(github)),
    ]);
  }

  if (scorecard) findings.push(...scorecardToFindings(scorecard, tool.name, { osvVulnCount: osvVulns.length }));
  if (osvVulns.length > 0) findings.push(...osvToFindings(osvVulns, tool.name));
  if (depsDevData && github) findings.push(...depsDevToFindings(depsDevData, tool.name, github));
  if (npmMeta)  findings.push(...npmMetaToFindings(npmMeta, tool.name));
  if (pypiMeta) findings.push(...pypiMetaToFindings(pypiMeta, tool.name));

  // Source code audit — only for major/deep modes and when GitHub is known
  if (mode !== "basic" && github) {
    logger.debug(`[oss] Crawling source code for ${tool.name} (${github})`);
    const sourceFindings = await crawlPackageSource(tool.name, github);
    findings.push(...sourceFindings);
  }

  const sourceFindingsCount = mode !== "basic" ? findings.filter(f => f.id.startsWith("source-")).length : 0;
  const depsDevScore = depsDevData?.scorecardV2?.score?.overall ?? depsDevData?.scorecard?.score;
  const deterministicRisk = scoreSupplyChainRisk({
    osvCount:         osvVulns.length,
    criticalFindings: findings.filter((finding) => finding.category === "supply-chain" && finding.severity === "critical").length,
    highFindings:     findings.filter((finding) => finding.category === "supply-chain" && finding.severity === "high").length,
    scorecardScore:   scorecard?.score,
    depsDevScore,
    maintainerCount:  npmMeta?.maintainers.length ?? pypiMeta?.maintainers.length,
    weeklyDownloads:  npmMeta?.weeklyDownloads ?? pypiMeta?.weeklyDownloads,
    publishedAt:      npmMeta?.publishedAt,
    sourceFindings:   sourceFindingsCount,
    deprecated:       Boolean(npmMeta?.deprecated),
    license:          npmMeta?.license,
  });

  const riskScore = await synthesizeRisk({
    tool:              tool.name,
    ecosystem,
    github,
    scorecardScore:    scorecard?.score,
    scorecardChecks:   scorecard?.checks.filter((c) => c.score < 5),
    osvCount:          osvVulns.length,
    osvIds:            osvVulns.map((v) => v.id),
    maintainerCount:   npmMeta?.maintainers.length ?? (pypiMeta?.maintainers.length),
    weeklyDownloads:   npmMeta?.weeklyDownloads ?? pypiMeta?.weeklyDownloads,
    depsDevScore,
    sourceFindings:    sourceFindingsCount,
    deprecated:        Boolean(npmMeta?.deprecated),
    license:           npmMeta?.license,
    deterministicRiskScore: deterministicRisk.score,
    deterministicRiskReasons: deterministicRisk.reasons,
    mode,
  }, deterministicRisk);

  return {
    tool:               { ...tool, github: github ?? tool.github },
    scorecard:          scorecard ?? undefined,
    osvVulnerabilities: osvVulns,
    depsDevData:        depsDevData ?? undefined,
    npmMeta:            npmMeta ?? undefined,
    findings,
    riskScore:          riskScore.score,
    aiSummary:          riskScore.summary,
  };
}

async function synthesizeRisk(
  data: Record<string, unknown>,
  deterministicRisk: SupplyChainRiskScore
): Promise<{ score: number; summary: string }> {
  try {
    const { content } = await complete({
      system: OSS_ANALYSIS_SYSTEM,
      messages: [{ role: "user", content: JSON.stringify(data, null, 2) }],
      temperature: 0.1,
      maxTokens: 512,
    });

    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(clean) as Record<string, unknown>;
    if (typeof parsed["riskScore"] !== "number" || typeof parsed["summary"] !== "string") {
      throw new Error("invalid shape");
    }
    const aiScore = Math.max(0, Math.min(100, Math.round(parsed["riskScore"] as number)));
    if (deterministicRisk.score > aiScore) {
      return { score: deterministicRisk.score, summary: deterministicRisk.summary };
    }
    return { score: aiScore, summary: parsed["summary"] as string };
  } catch {
    return deterministicRisk;
  }
}
