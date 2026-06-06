import { complete } from "./ai.js";
import { logger } from "./logger.js";
import type { Finding, Severity, TriageDecision } from "./types.js";

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const CVE_LIMIT = 200;

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface NoiseGateOptions {
  showNoise?: boolean;
  allCves?: boolean;
  llmTriage?: boolean;
}

export interface NoiseGateMetadata {
  enabled: boolean;
  shown: number;
  review: number;
  hidden: number;
  showNoise: boolean;
  allCves: boolean;
  llmTriage: boolean;
  reviewFindings: Finding[];
  hiddenFindings: Finding[];
  hiddenByCategory: Record<string, number>;
}

export interface NoiseGateResult {
  findings: Finding[];
  rawFindings: Finding[];
  reviewFindings: Finding[];
  hiddenFindings: Finding[];
  metadata: NoiseGateMetadata;
}

interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
}

interface EpssResponse {
  data?: Array<{ cve?: string; epss?: string; percentile?: string }>;
}

interface KevResponse {
  vulnerabilities?: Array<{ cveID?: string }>;
}

interface LlmTriageItem {
  id: string;
  decision: TriageDecision;
  reason: string;
  confidence?: "high" | "medium" | "low";
}

interface LlmTriageResponse {
  findings?: LlmTriageItem[];
}

let kevCache: Set<string> | null = null;

export async function applyNoiseGate(
  findings: Finding[],
  options: NoiseGateOptions = {},
): Promise<NoiseGateResult> {
  const base = await enrichVulnerabilityIntelligence(findings.map((finding) => ({ ...finding })));
  let triaged = base.map(applyDeterministicTriage);

  if (options.llmTriage) {
    triaged = await applyLlmTriage(triaged);
  }

  const reviewFindings = triaged.filter((finding) => finding.triageDecision === "review");
  const hiddenFindings = triaged.filter((finding) => finding.triageDecision === "hide");
  const reportFindings = triaged.filter((finding) => shouldIncludeInReport(finding, options));

  return {
    findings: reportFindings,
    rawFindings: triaged,
    reviewFindings,
    hiddenFindings,
    metadata: {
      enabled: true,
      shown: triaged.filter((finding) => finding.triageDecision === "show").length,
      review: reviewFindings.length,
      hidden: hiddenFindings.length,
      showNoise: Boolean(options.showNoise),
      allCves: Boolean(options.allCves),
      llmTriage: Boolean(options.llmTriage),
      reviewFindings,
      hiddenFindings,
      hiddenByCategory: countByCategory(hiddenFindings),
    },
  };
}

export function applyDeterministicTriage(finding: Finding): Finding {
  if (isVulnerabilityFinding(finding)) return triageVulnerabilityFinding(finding);
  if (finding.category === "blackbox" || finding.category === "smoke") return triageProbeFinding(finding);
  return decorate(finding, "show", finding.triageReason ?? "Confirmed scanner finding.", finding.signals);
}

export function isVulnerabilityFinding(finding: Finding): boolean {
  const advisorySignals = new Set(finding.signals ?? []);
  return (
    finding.id.startsWith("osv-") ||
    (finding.relatedVulnerabilities?.length ?? 0) > 0 ||
    extractCveIds(finding).length > 0 ||
    advisorySignals.has("osv-version-match")
  );
}

export function extractCveIds(finding: Finding): string[] {
  const text = [
    finding.id,
    finding.title,
    finding.description,
    finding.detail,
    finding.references?.join(" "),
    finding.relatedVulnerabilities?.flatMap((v) => [v.id, ...(v.aliases ?? [])]).join(" "),
  ].filter(Boolean).join(" ");

  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
  return [...new Set(matches.map((match) => match.toUpperCase()))];
}

function triageVulnerabilityFinding(finding: Finding): Finding {
  const signals = new Set(finding.signals ?? []);
  const rank = SEVERITY_RANK[finding.severity];
  const depth = finding.dependencyDepth;
  const isDirect = depth === 0 || signals.has("direct-dependency");
  const isTransitive = depth !== undefined && depth > 0 || signals.has("transitive-dependency");

  if (finding.vexStatus === "not_affected" || finding.vexStatus === "fixed") {
    return decorate(finding, "hide", `VEX marks this vulnerability as ${finding.vexStatus}.`, signals);
  }

  if (hasAnySignal(signals, ["cisa-kev", "public-exploit", "exploit-template", "nuclei-template", "reachable-code", "high-epss"])) {
    return decorate(finding, "show", "Known exploitation, exploitability, or reachability evidence makes this actionable.", signals);
  }

  if (isDirect && rank >= SEVERITY_RANK.high) {
    return decorate(finding, "show", "Direct high/critical dependency vulnerability with no suppressing VEX status.", signals);
  }

  if (isTransitive && rank >= SEVERITY_RANK.high) {
    return decorate(finding, "review", "Transitive high/critical dependency vulnerability without exploit or reachability evidence.", signals);
  }

  if (rank === SEVERITY_RANK.medium && signals.has("medium-epss")) {
    return decorate(finding, "review", "Medium-severity vulnerability has elevated EPSS and should be reviewed.", signals);
  }

  if (rank === SEVERITY_RANK.medium && finding.fixedVersion) {
    return decorate(finding, "review", "Medium-severity vulnerability has a known fix path but lacks exploit or reachability evidence.", signals);
  }

  return decorate(finding, "hide", "No exploit, reachability, KEV, elevated EPSS, or direct high-severity signal was found.", signals);
}

function triageProbeFinding(finding: Finding): Finding {
  const signals = new Set(finding.signals ?? []);

  if (hasAnySignal(signals, ["confirmed-sensitive-exposure", "confirmed-auth-bypass", "confirmed-stack-trace"])) {
    return decorate(finding, "show", "Probe produced concrete sensitive evidence.", signals);
  }

  if (finding.id === "smoke-unreachable" || finding.id === "smoke-server-error") {
    return decorate(finding, "show", "The service is unreachable or returning server errors.", signals);
  }

  if (finding.id === "cors-origin-reflection" || finding.id === "http-trace-enabled") {
    return decorate(finding, "show", "The probe confirmed a security-impacting server behavior.", signals);
  }

  if (finding.id === "cors-wildcard-credentials" || finding.id === "smoke-no-payload-limit") {
    return decorate(finding, "review", "The probe found a hardening issue that needs context before it should fail CI.", signals);
  }

  if (finding.id.startsWith("header-missing-")) {
    const header = finding.id.replace("header-missing-", "");
    const decision: TriageDecision = header === "strict-transport-security" || header === "content-security-policy"
      ? "review"
      : "hide";
    return decorate(finding, decision, "Missing browser hardening headers are kept out of the default report unless stronger impact evidence exists.", signals);
  }

  if (finding.id.startsWith("exposed-path-")) {
    return decorate(finding, "review", "The path responded, but BreachScope did not confirm sensitive content.", signals);
  }

  if (finding.evidenceStrength === "confirmed" || finding.evidenceStrength === "strong") {
    return decorate(finding, "show", "The probe produced strong evidence.", signals);
  }

  return decorate(finding, "hide", "Probe evidence is weak or informational without confirmed security impact.", signals);
}

function decorate(
  finding: Finding,
  decision: TriageDecision,
  reason: string,
  inputSignals?: Iterable<string>,
): Finding {
  const signals = [...new Set(inputSignals ? [...inputSignals] : finding.signals ?? [])];
  return {
    ...finding,
    triageDecision: decision,
    triageReason: reason,
    showByDefault: decision === "show",
    signals,
  };
}

function shouldIncludeInReport(finding: Finding, options: NoiseGateOptions): boolean {
  if (finding.triageDecision === "show") return true;
  if (options.showNoise) return true;
  if (options.allCves && isVulnerabilityFinding(finding)) return true;
  return false;
}

async function enrichVulnerabilityIntelligence(findings: Finding[]): Promise<Finding[]> {
  const cves = [...new Set(findings.flatMap(extractCveIds))].slice(0, CVE_LIMIT);
  if (cves.length === 0) return findings;

  const [kev, epss] = await Promise.all([
    fetchKevCves(),
    fetchEpss(cves),
  ]);

  return findings.map((finding) => {
    const findingCves = extractCveIds(finding);
    if (findingCves.length === 0) return finding;

    const signals = new Set(finding.signals ?? []);
    const kevMatches = findingCves.filter((cve) => kev.has(cve));
    const epssEntries = findingCves.map((cve) => epss.get(cve)).filter((entry): entry is EpssEntry => Boolean(entry));
    const maxEpss = epssEntries.reduce((max, entry) => Math.max(max, entry.epss), 0);
    const maxPercentile = epssEntries.reduce((max, entry) => Math.max(max, entry.percentile), 0);

    if (kevMatches.length > 0) signals.add("cisa-kev");
    if (maxEpss >= 0.1 || maxPercentile >= 0.9) signals.add("high-epss");
    else if (maxEpss >= 0.02 || maxPercentile >= 0.75) signals.add("medium-epss");

    const detailParts = [
      finding.detail,
      kevMatches.length > 0 ? `CISA KEV: ${kevMatches.join(", ")}` : null,
      epssEntries.length > 0 ? `Max EPSS: ${(maxEpss * 100).toFixed(2)}% (${Math.round(maxPercentile * 100)}th percentile)` : null,
    ].filter(Boolean);

    return {
      ...finding,
      signals: [...signals],
      confidence: finding.confidence ?? (kevMatches.length > 0 || maxEpss >= 0.1 ? "high" : "medium"),
      detail: detailParts.join(" | "),
    };
  });
}

async function fetchKevCves(): Promise<Set<string>> {
  if (kevCache) return kevCache;
  try {
    const res = await fetch(CISA_KEV_URL, {
      headers: { "User-Agent": "BreachScope/1.0" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return new Set();
    const body = await res.json() as KevResponse;
    kevCache = new Set((body.vulnerabilities ?? [])
      .map((entry) => entry.cveID?.toUpperCase())
      .filter((id): id is string => Boolean(id)));
    return kevCache;
  } catch (e) {
    logger.debug(`[noise-gate] CISA KEV fetch failed: ${e}`);
    return new Set();
  }
}

async function fetchEpss(cves: string[]): Promise<Map<string, EpssEntry>> {
  const results = new Map<string, EpssEntry>();
  const chunks = chunk(cves, 100);

  for (const cveChunk of chunks) {
    try {
      const url = `${EPSS_URL}?cve=${encodeURIComponent(cveChunk.join(","))}`;
      const res = await fetch(url, {
        headers: { "User-Agent": "BreachScope/1.0" },
        signal: AbortSignal.timeout(8_000),
      });
      if (!res.ok) continue;
      const body = await res.json() as EpssResponse;
      for (const entry of body.data ?? []) {
        if (!entry.cve) continue;
        results.set(entry.cve.toUpperCase(), {
          cve: entry.cve.toUpperCase(),
          epss: Number.parseFloat(entry.epss ?? "0") || 0,
          percentile: Number.parseFloat(entry.percentile ?? "0") || 0,
        });
      }
    } catch (e) {
      logger.debug(`[noise-gate] EPSS fetch failed: ${e}`);
    }
  }

  return results;
}

async function applyLlmTriage(findings: Finding[]): Promise<Finding[]> {
  const candidates = findings
    .filter((finding) => finding.triageDecision === "review")
    .filter((finding) => isVulnerabilityFinding(finding) || finding.category === "blackbox" || finding.category === "smoke")
    .slice(0, 25);

  if (candidates.length === 0) return findings;

  try {
    const { content } = await complete({
      system: `You are a security triage reviewer. Decide whether each finding should be shown, reviewed, or hidden.
Return only JSON: {"findings":[{"id":"...","decision":"show|review|hide","reason":"one sentence","confidence":"high|medium|low"}]}.
Do not hide findings with CISA KEV, high EPSS, direct high/critical severity, confirmed sensitive exposure, confirmed auth bypass, or confirmed exploit evidence.`,
      messages: [{
        role: "user",
        content: JSON.stringify(candidates.map((finding) => ({
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          confidence: finding.confidence,
          evidenceStrength: finding.evidenceStrength,
          signals: finding.signals,
          dependencyDepth: finding.dependencyDepth,
          dependencyScope: finding.dependencyScope,
          triageDecision: finding.triageDecision,
          triageReason: finding.triageReason,
          description: finding.description.slice(0, 500),
          detail: finding.detail?.slice(0, 500),
        }))),
      }],
      temperature: 0.05,
      maxTokens: 1600,
    });

    const parsed = JSON.parse(content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim()) as LlmTriageResponse;
    const byId = new Map((parsed.findings ?? []).map((item) => [item.id, item]));
    return findings.map((finding) => {
      const item = byId.get(finding.id);
      if (!item) return finding;
      const decision = normalizeDecision(item.decision);
      if (!decision) return finding;
      if (decision === "hide" && isProtectedFinding(finding)) return finding;
      return {
        ...finding,
        triageDecision: decision,
        triageReason: `LLM triage: ${item.reason || "No reason supplied."}`,
        confidence: item.confidence ?? finding.confidence,
        showByDefault: decision === "show",
        signals: [...new Set([...(finding.signals ?? []), "llm-triage"])],
      };
    });
  } catch (e) {
    logger.warn(`LLM triage skipped: ${e instanceof Error ? e.message : String(e)}`);
    return findings;
  }
}

function isProtectedFinding(finding: Finding): boolean {
  const signals = new Set(finding.signals ?? []);
  return (
    hasAnySignal(signals, ["cisa-kev", "high-epss", "public-exploit", "confirmed-sensitive-exposure", "confirmed-auth-bypass"]) ||
    (SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.high && finding.dependencyDepth === 0) ||
    (finding.evidenceStrength === "confirmed" && SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.high)
  );
}

function normalizeDecision(value: string): TriageDecision | null {
  if (value === "show" || value === "review" || value === "hide") return value;
  return null;
}

function hasAnySignal(signals: Set<string>, names: string[]): boolean {
  return names.some((name) => signals.has(name));
}

function countByCategory(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.category] = (acc[finding.category] ?? 0) + 1;
    return acc;
  }, {});
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}
