import type { GitHubAuditResult } from "./github-audit";

export interface AuditSynthesis {
  executiveSummary: string;
  criticalPath?: string;
  topPriority?: string;
  attackChains?: Array<{
    title: string;
    severity: string;
    steps: string[];
    impact: string;
  }>;
  model?: string;
  providerError?: string;
}

export interface AuditSynthesisResult {
  synthesis: AuditSynthesis;
  tokensUsed: number;
}

const DEFAULT_MODEL = "gpt-4.1";

export async function buildGitHubAiSynthesis(opts: {
  audit: GitHubAuditResult;
  openaiKey?: string | null;
}): Promise<AuditSynthesisResult> {
  if (!opts.openaiKey) {
    return { synthesis: deterministicSynthesis(opts.audit), tokensUsed: 0 };
  }

  const model = process.env["OPENAI_AUDIT_MODEL"]?.trim() || DEFAULT_MODEL;
  const prompt = {
    repository: opts.audit.repoFullName,
    defaultBranch: opts.audit.defaultBranch,
    visibility: opts.audit.visibility,
    findings: opts.audit.findings.slice(0, 30).map((finding) => ({
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      remediation: finding.remediation,
    })),
    pullRequest: opts.audit.pullRequest ? {
      number: opts.audit.pullRequest.number,
      title: opts.audit.pullRequest.title,
      author: opts.audit.pullRequest.author,
      additions: opts.audit.pullRequest.additions,
      deletions: opts.audit.pullRequest.deletions,
      changedFiles: opts.audit.pullRequest.changedFiles,
      files: opts.audit.pullRequest.files.slice(0, 60).map((file) => file.filename),
    } : null,
  };

  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${opts.openaiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: [
              "You are a senior application security reviewer.",
              "Return compact JSON only with executiveSummary, topPriority, criticalPath, and attackChains.",
              "Do not invent facts. Base every claim on the supplied audit findings and pull request metadata.",
            ].join(" "),
          },
          { role: "user", content: JSON.stringify(prompt) },
        ],
      }),
    });

    const text = await res.text();
    if (!res.ok) {
      return { synthesis: { ...deterministicSynthesis(opts.audit), model, providerError: text.slice(0, 300) }, tokensUsed: 0 };
    }

    const body = JSON.parse(text) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { total_tokens?: number };
    };
    const content = body.choices?.[0]?.message?.content ?? "";
    const parsed = JSON.parse(content) as Partial<AuditSynthesis>;

    return {
      synthesis: {
        executiveSummary: stringOr(parsed.executiveSummary, deterministicSynthesis(opts.audit).executiveSummary),
        criticalPath: typeof parsed.criticalPath === "string" ? parsed.criticalPath.slice(0, 1000) : undefined,
        topPriority: typeof parsed.topPriority === "string" ? parsed.topPriority.slice(0, 1000) : undefined,
        attackChains: Array.isArray(parsed.attackChains) ? parsed.attackChains.slice(0, 5).map((chain) => ({
          title: stringOr(chain.title, "Audit path").slice(0, 180),
          severity: stringOr(chain.severity, "medium").slice(0, 40),
          steps: Array.isArray(chain.steps) ? chain.steps.slice(0, 8).map((step) => String(step).slice(0, 240)) : [],
          impact: stringOr(chain.impact, "").slice(0, 500),
        })) : undefined,
        model,
      },
      tokensUsed: body.usage?.total_tokens ?? 0,
    };
  } catch (error) {
    return {
      synthesis: {
        ...deterministicSynthesis(opts.audit),
        model,
        providerError: error instanceof Error ? error.message.slice(0, 300) : "OpenAI audit synthesis failed.",
      },
      tokensUsed: 0,
    };
  }
}

function deterministicSynthesis(audit: GitHubAuditResult): AuditSynthesis {
  const critical = audit.findings.filter((finding) => finding.severity === "critical").length;
  const high = audit.findings.filter((finding) => finding.severity === "high").length;
  const medium = audit.findings.filter((finding) => finding.severity === "medium").length;
  const top = audit.findings.find((finding) => finding.severity === "critical")
    ?? audit.findings.find((finding) => finding.severity === "high")
    ?? audit.findings[0];

  return {
    executiveSummary: `${audit.repoFullName} was audited for repository controls, branch protection, GitHub Actions posture, CODEOWNERS coverage, workflow pinning, and pull request risk. The audit found ${critical} critical, ${high} high, and ${medium} medium issue(s).`,
    topPriority: top ? `${top.title}: ${top.remediation ?? top.description}` : "No priority action was identified in the current audit.",
    criticalPath: audit.pullRequest
      ? `Review pull request #${audit.pullRequest.number}, confirm sensitive changes have owner approval, and keep required checks enforced before merge.`
      : `Harden ${audit.defaultBranch} branch controls first, then review Actions permissions and repository code-security settings.`,
    attackChains: top ? [{
      title: "Repository control bypass path",
      severity: top.severity,
      steps: [
        "A risky repository or workflow setting weakens the expected review gate.",
        "A malicious or compromised contributor can push or merge code with reduced friction.",
        "CI or deployment automation can move the change into a trusted environment.",
      ],
      impact: top.description,
    }] : [],
  };
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}
