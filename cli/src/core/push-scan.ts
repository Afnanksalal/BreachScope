import path from "path";
import { resolveCredentials } from "./auth.js";
import { logger } from "./logger.js";
import type { Finding, ScanResult } from "./types.js";
import type { AttackLogEntry, SandboxMemorySnapshot } from "../agents/sandbox-agent.js";

const DASHBOARD_PUSH_TIMEOUT_MS = 10000;

export interface ToolRiskEntry {
  name: string;
  kind: string;
  depth: number;
  parent?: string;
  riskScore: number;
  aiSummary?: string;
  osvCount: number;
  osvIds?: string[];
  scorecardScore?: number;
  weeklyDownloads?: number;
  maintainerCount?: number;
  findingsCount: number;
  github?: string;   // https://github.com/org/repo
  version?: string;  // installed version
}

export interface ProbeData {
  services?: Array<{ id: string; name: string; category: string; steps: string[]; findingsCount: number; tokensUsed: number }>;
  sandbox?: {
    projectType: string;
    attackLog: AttackLogEntry[];
    attackChains: string[];
    findingsCount: number;
    tokensUsed: number;
    memorySnapshot?: SandboxMemorySnapshot;
  };
}

export async function pushScanToDashboard(
  result: ScanResult,
  opts: {
    mode: string;
    scanMode: string;
    url?: string;
    toolsScanned?: number;
    toolRiskData?: ToolRiskEntry[];
    probeData?: ProbeData;
    aiReport?: string;
  }
): Promise<string | null> {
  const creds = resolveCredentials();
  if (!creds) return null;

  const project = path.basename(result.target);

  const body = {
    project,
    mode:         opts.mode,
    scanMode:     opts.scanMode,
    target:       result.target,
    url:          opts.url ?? null,
    startedAt:    result.startedAt.toISOString(),
    completedAt:  result.completedAt.toISOString(),
    toolsScanned: opts.toolsScanned ?? 0,
    riskData:     opts.toolRiskData ? JSON.stringify(opts.toolRiskData) : undefined,
    probeData:    opts.probeData    ? JSON.stringify(opts.probeData)    : undefined,
    aiReport:     opts.aiReport     ?? undefined,
    findings:     result.findings.map((f: Finding) => ({
      title:       f.title,
      severity:    f.severity,
      category:    f.category,
      description: f.description,
      detail:      formatFindingDetail(f),
      remediation: f.remediation ?? undefined,
      tool:        f.tool        ?? undefined,
      file:        f.file        ?? undefined,
      line:        f.line        ?? undefined,
      references:  f.references  ?? undefined,
      fingerprint: f.fingerprint ?? undefined,
      status:      f.status      ?? undefined,
      compliance:  f.compliance  ?? undefined,
      vexStatus:   f.vexStatus   ?? undefined,
    })),
  };

  try {
    const res = await fetch(`${creds.dashboardUrl}/api/scans`, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${creds.token}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(DASHBOARD_PUSH_TIMEOUT_MS),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      logger.debug(`Dashboard push failed: ${res.status} ${text}`);
      return null;
    }

    const data = await res.json() as { id: string };
    return data.id ?? null;
  } catch (e) {
    logger.debug(`Dashboard push error: ${e}`);
    return null;
  }
}

function formatFindingDetail(finding: Finding): string | undefined {
  const triage = [
    finding.triageDecision ? `Triage: ${finding.triageDecision}` : null,
    finding.triageReason ? `Reason: ${finding.triageReason}` : null,
    finding.confidence ? `Confidence: ${finding.confidence}` : null,
    finding.evidenceStrength ? `Evidence: ${finding.evidenceStrength}` : null,
    finding.signals?.length ? `Signals: ${finding.signals.join(", ")}` : null,
  ].filter(Boolean).join("\n");

  const detail = [finding.detail, triage || null].filter(Boolean).join("\n\n");
  return detail || undefined;
}
