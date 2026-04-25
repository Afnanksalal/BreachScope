// ─── Severity & base scan types ──────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanTarget =
  | "dependency"
  | "toolchain"
  | "code"
  | "blackbox"
  | "smoke"
  | "all";

/** basic = direct tools only | major = +1 level sub-deps | deep = full transitive tree */
export type ScanMode = "basic" | "major" | "deep";

export type ToolKind = "oss" | "saas" | "hybrid" | "unknown";

export type DetectionSource =
  | "package.json"
  | "import-statement"
  | "env-variable"
  | "config-file"
  | "sub-dependency";

// ─── Finding ─────────────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: ScanTarget | "supply-chain";
  description: string;
  detail?: string;
  remediation?: string;
  references?: string[];
  tool?: string;
  file?: string;
  line?: number;
}

// ─── Detected tool model ──────────────────────────────────────────────────────

export interface DetectedTool {
  /** Package name */
  name: string;
  /** Version range from manifest, if available */
  version?: string;
  /** OSS, SaaS, hybrid (has both npm SDK + hosted service), or unknown */
  kind: ToolKind;
  /** GitHub "org/repo" — only for oss/hybrid */
  github?: string;
  /** Service homepage or docs URL */
  homepage?: string;
  /** How this tool was found */
  detectedFrom: DetectionSource[];
  /** 0 = direct dep, 1 = its dep, 2 = its dep's dep … */
  depth: number;
  /** Parent tool that introduced this as a sub-dep */
  parent?: string;
  /** Package ecosystem: npm | PyPI | Go | crates.io | RubyGems (default: npm) */
  ecosystem?: string;
}

// ─── External API results ─────────────────────────────────────────────────────

export interface ScorecardResult {
  score: number;
  date: string;
  repo: string;
  checks: ScorecardCheck[];
}

export interface ScorecardCheck {
  name: string;
  score: number;
  reason: string;
  documentation?: { url: string };
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  aliases?: string[];                                    // e.g. ["CVE-2024-1234", "GHSA-xxxx"]
  /** OSV returns severity as an array of CVSS score objects, not a plain string */
  severity?: Array<{ type: string; score: string }> | string;
  database_specific?: { severity?: string };
  ecosystem_specific?: { severity?: string };
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references: Array<{ type: string; url: string }>;
  modified: string;
  published?: string;
}

export interface DepsDevProject {
  projectKey: { id: string };
  openIssuesCount?: number;
  starsCount?: number;
  forksCount?: number;
  scorecard?: { score: number };
  scorecardV2?: { score: { overall: number } };
}

export interface NpmPackageMeta {
  name: string;
  version: string;
  description?: string;
  maintainers: Array<{ name: string; email: string }>;
  weeklyDownloads?: number;
  publishedAt?: string;
  repository?: string;
  dependencies: Record<string, string>;
}

// ─── Pipeline results ─────────────────────────────────────────────────────────

export interface ToolPipelineResult {
  tool: DetectedTool;
  scorecard?: ScorecardResult;
  osvVulnerabilities: OsvVulnerability[];
  depsDevData?: DepsDevProject;
  npmMeta?: NpmPackageMeta;
  findings: Finding[];
  riskScore: number;         // 0–100 composite
  aiSummary?: string;
}

export interface SubchainScanResult {
  mode: ScanMode;
  toolsScanned: number;
  depthReached: number;
  toolResults: ToolPipelineResult[];
  allFindings: Finding[];
  graph: DependencyGraph;
}

export interface DependencyGraph {
  nodes: Array<{ id: string; kind: ToolKind; riskScore: number; depth: number }>;
  edges: Array<{ from: string; to: string }>;
}

// ─── Scan config & options ────────────────────────────────────────────────────

export interface ScanResult {
  target: string;
  startedAt: Date;
  completedAt: Date;
  findings: Finding[];
  summary: ScanSummary;
  metadata: Record<string, unknown>;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface BreachScopeConfig {
  version: string;
  project?: string;
  targets: ScanTarget[];
  toolchain: ToolchainConfig;
  ai?: AIConfig;
  output: OutputConfig;
  thresholds: ThresholdConfig;
  subchain?: SubchainConfig;
}

export interface SubchainConfig {
  /** Max recursion depth for "deep" mode (default: 6) */
  maxDepth?: number;
  /** Max concurrent tool scans (default: 5) */
  concurrency?: number;
  /** Skip packages matching these patterns */
  ignore?: string[];
}

export interface AIConfig {
  openaiApiKey?: string;
  firecrawlApiKey?: string;
  model?: string;
  maxTokensPerAgent?: number;
}

export interface ToolchainConfig {
  supabase?: { url?: string; anonKey?: string };
  vercel?: { token?: string; projectId?: string };
  github?: { token?: string; repo?: string };
  custom?: Array<{ name: string; url: string; headers?: Record<string, string> }>;
}

export interface OutputConfig {
  format: "console" | "json" | "html" | "sarif";
  file?: string;
  verbose: boolean;
}

export interface ThresholdConfig {
  failOn: Severity;
  maxCritical?: number;
  maxHigh?: number;
}

export interface ScanOptions {
  target?: ScanTarget;
  mode?: ScanMode;
  /** "breach" | "bug" | "all" — set by --breach / --bug flags */
  scanMode?: string;
  output?: OutputConfig["format"];
  file?: string;
  verbose?: boolean;
  config?: string;
  tool?: string;
  url?: string;
  ci?: boolean;
  ai?: boolean;
  browser?: boolean;
}

// ─── AI / Agent layer ─────────────────────────────────────────────────────────

export type AgentName =
  | "orchestrator"
  | "dependency"
  | "code"
  | "toolchain"
  | "blackbox"
  | "report";

export interface AgentContext {
  files: Record<string, string>;
  packageJson?: Record<string, unknown>;
  dependencies: string[];
  url?: string;
  toolchain: ToolchainConfig;
  existingFindings: Finding[];
  crawlCache: Record<string, string>;
  /** "breach" | "bug" | "all" — controls agent focus and system prompt */
  scanMode?: string;
}

export interface AgentResult {
  agent: AgentName;
  findings: Finding[];
  reasoning: string;
  sourcesCrawled: string[];
  tokensUsed: number;
}

export interface OrchestratorPlan {
  agents: AgentName[];
  rationale: string;
}
