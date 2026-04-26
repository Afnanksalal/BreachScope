import { agentLoop } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

export type ValidationConfidence = "confirmed" | "likely" | "uncertain" | "false_positive";

export interface ValidationResult {
  finding_id: string;
  reproducible: boolean;
  reproducibility_score: number;  // 0–100
  confidence: ValidationConfidence;
  validation_notes: string;
  attempts: number;
  reproduced_evidence?: string;
}

type ExecFn = (cmd: string[], timeoutMs?: number) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

const VALIDATOR_SYSTEM = `You are a meticulous security researcher tasked with INDEPENDENTLY VERIFYING a reported vulnerability.

Your job is to reproduce the finding from scratch using ONLY the steps_to_replicate and evidence provided. You must:
1. Run each replication step EXACTLY as described
2. Confirm the response matches the expected evidence
3. Record what actually happened vs what was claimed

You must be SKEPTICAL. Many AI-reported findings are:
- False positives where the evidence was misinterpreted
- Based on command output that looked like a vuln but wasn't
- Speculative (e.g., "this MIGHT be vulnerable")

Only mark as confirmed if you can independently reproduce the SAME evidence.

After 3 attempts, call submit_validation with your assessment.`;

const VALIDATOR_TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "exec_cmd",
      description: "Execute a shell command to reproduce the vulnerability step.",
      parameters: {
        type: "object",
        properties: {
          cmd: { type: "array", items: { type: "string" } },
          timeout_seconds: { type: "number" },
        },
        required: ["cmd"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "http_request",
      description: "Make an HTTP request to verify the vulnerability.",
      parameters: {
        type: "object",
        properties: {
          method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] },
          url: { type: "string" },
          headers: { type: "object", additionalProperties: { type: "string" } },
          body: { type: "string" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "submit_validation",
      description: "Submit the validation result after attempting to reproduce the finding.",
      parameters: {
        type: "object",
        properties: {
          reproducible: {
            type: "boolean",
            description: "Could you independently reproduce this vulnerability?",
          },
          reproducibility_score: {
            type: "number",
            description: "0–100 confidence score. 90–100=confirmed, 60–89=likely, 30–59=uncertain, 0–29=false positive",
          },
          validation_notes: {
            type: "string",
            description: "What you tried, what you got, what matched vs didn't match the claimed evidence. Be specific.",
          },
          reproduced_evidence: {
            type: "string",
            description: "The actual command output or HTTP response that confirms the vulnerability (if reproduced).",
          },
        },
        required: ["reproducible", "reproducibility_score", "validation_notes"],
      },
    },
  },
];

export async function validateFinding(
  findingId: string,
  title: string,
  severity: string,
  stepsToReplicate: string,
  evidence: string,
  baseUrl: string,
  execFn: ExecFn,
): Promise<ValidationResult> {
  // Only validate critical and high to avoid burning tokens on low-impact findings
  if (severity !== "critical" && severity !== "high") {
    return {
      finding_id: findingId,
      reproducible: true,
      reproducibility_score: 70,
      confidence: "likely",
      validation_notes: "Validation skipped for medium/low severity findings.",
      attempts: 0,
    };
  }

  let result: ValidationResult = {
    finding_id: findingId,
    reproducible: false,
    reproducibility_score: 0,
    confidence: "uncertain",
    validation_notes: "Validation did not complete.",
    attempts: 0,
  };

  const userMessage = `VERIFY THIS SECURITY FINDING

Finding ID: ${findingId}
Title: ${title}
Severity: ${severity}

STEPS TO REPLICATE (from original discoverer):
${stepsToReplicate || "No replication steps provided — use the evidence to infer the steps."}

ORIGINAL EVIDENCE:
${evidence.slice(0, 2000)}

TARGET: ${baseUrl}

YOUR TASK:
1. Execute each replication step exactly
2. Capture the response and compare to the original evidence
3. Try up to 3 different approaches if the first attempt fails
4. Call submit_validation with your honest assessment

IMPORTANT: If the steps are vague or the evidence is just "command output" without a clear exploit, score it accordingly.
A CVSS 9.0 finding that can't be reproduced is a false positive — don't give it a high score.`;

  try {
    const loopResult = await agentLoop(
      {
        system: VALIDATOR_SYSTEM,
        messages: [{ role: "user", content: userMessage }],
        tools: VALIDATOR_TOOLS,
        temperature: 0.05,
        maxTokens: 4096,
        maxIterations: 12,
      },
      async (toolName, args) => {
        const a = args as Record<string, unknown>;
        // Count reproduction attempts (exec/http), not submit_validation itself
        if (toolName === "exec_cmd" || toolName === "http_request") result.attempts++;

        if (toolName === "exec_cmd") {
          const cmd = a["cmd"] as string[];
          const timeout = Number(a["timeout_seconds"] ?? 30) * 1000;
          try {
            const r = await execFn(cmd, timeout);
            return JSON.stringify({
              stdout: r.stdout.slice(0, 3000),
              stderr: r.stderr.slice(0, 1000),
              exit_code: r.exitCode,
            });
          } catch (e) {
            return JSON.stringify({ error: String(e) });
          }
        }

        if (toolName === "http_request") {
          const method = String(a["method"] ?? "GET");
          const url = String(a["url"] ?? "");
          const headers = (a["headers"] as Record<string, string>) ?? {};
          const body = a["body"] ? String(a["body"]) : undefined;
          try {
            const resp = await fetch(url, {
              method,
              headers: { "Content-Type": "application/json", ...headers },
              body,
              signal: AbortSignal.timeout(10_000),
            });
            const text = (await resp.text()).slice(0, 3000);
            const respHeaders: Record<string, string> = {};
            resp.headers.forEach((v, k) => { respHeaders[k] = v; });
            return JSON.stringify({ status: resp.status, headers: respHeaders, body: text });
          } catch (e) {
            return JSON.stringify({ error: String(e) });
          }
        }

        if (toolName === "submit_validation") {
          const score = Number(a["reproducibility_score"] ?? 0);
          const reproducible = Boolean(a["reproducible"] ?? false);
          const notes = String(a["validation_notes"] ?? "");
          const repEvidence = a["reproduced_evidence"] ? String(a["reproduced_evidence"]) : undefined;

          let confidence: ValidationConfidence;
          if (score >= 90) confidence = "confirmed";
          else if (score >= 60) confidence = "likely";
          else if (score >= 30) confidence = "uncertain";
          else confidence = "false_positive";

          result = {
            finding_id: findingId,
            reproducible,
            reproducibility_score: score,
            confidence,
            validation_notes: notes,
            attempts: result.attempts,
            reproduced_evidence: repEvidence,
          };

          logger.debug(`[validator] ${findingId}: ${confidence} (${score}/100) — ${notes.slice(0, 80)}`);
          return JSON.stringify({ success: true, confidence, score });
        }

        return JSON.stringify({ error: `Unknown tool: ${toolName}` });
      }
    );
    // If agent finished without calling submit_validation, flag it explicitly
    if (result.validation_notes === "Validation did not complete.") {
      result.validation_notes = `Validator agent ran ${result.attempts} tool call(s) but never called submit_validation. Agent output: ${loopResult.content.slice(0, 200)}`;
      result.reproducibility_score = 50;
      result.confidence = "uncertain";
    }
  } catch (e) {
    logger.debug(`[validator] Error validating ${findingId}: ${e}`);
    result.validation_notes = `Validator crashed: ${String(e).slice(0, 150)}`;
    result.confidence = "uncertain";
  }

  return result;
}

/** Validate multiple findings in sequence, returning a map of finding_id → ValidationResult */
export async function validateFindings(
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    steps_to_replicate: string;
    evidence: string;
  }>,
  baseUrl: string,
  execFn: ExecFn,
): Promise<Map<string, ValidationResult>> {
  const results = new Map<string, ValidationResult>();

  // Only validate critical/high
  const toValidate = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  ).slice(0, 5); // cap at 5 to avoid excessive token use

  for (const f of toValidate) {
    const vr = await validateFinding(
      f.id,
      f.title,
      f.severity,
      f.steps_to_replicate,
      f.evidence,
      baseUrl,
      execFn,
    );
    results.set(f.id, vr);
  }

  return results;
}
