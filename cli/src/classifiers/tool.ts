import { complete } from "../core/ai.js";
import { resolveKnownTool } from "../core/toolmap.js";
import { logger } from "../core/logger.js";
import type { DetectedTool, ToolKind } from "../core/types.js";

interface ClassifiedTool {
  name: string;
  kind: ToolKind;
  github?: string;
  homepage?: string;
  displayName?: string;
  hasSaas?: boolean;
  confidence: "high" | "medium" | "low";
}

const CLASSIFY_SYSTEM = `You are a software supply-chain analyst. Given a list of npm package names, classify each one.

For each package return:
{
  "name": "exact package name",
  "kind": "oss" | "saas" | "hybrid" | "unknown",
  "github": "org/repo or null",
  "homepage": "website URL or null",
  "displayName": "human-readable service name",
  "hasSaas": true/false,
  "confidence": "high" | "medium" | "low"
}

Definitions:
- "oss": open-source library, no hosted SaaS component (e.g., lodash, chalk, zod)
- "saas": pure SaaS SDK — the package is only useful with a paid/hosted service (e.g., a Stripe-only package)
- "hybrid": package that is open-source AND connects to a hosted service (e.g., @supabase/supabase-js, openai SDK)
- "unknown": you're not confident

Return ONLY a JSON array. No explanation outside the JSON.`;

/**
 * Classify a batch of DetectedTools that weren't in the known-tools map.
 * Uses GPT-4o with a batch prompt to minimize API calls.
 */
export async function classifyUnknownTools(tools: DetectedTool[]): Promise<DetectedTool[]> {
  if (tools.length === 0) return [];

  const BATCH_SIZE = 30;
  const result: DetectedTool[] = [];

  for (let i = 0; i < tools.length; i += BATCH_SIZE) {
    const batch = tools.slice(i, i + BATCH_SIZE);
    const names = batch.map((t) => t.name);

    logger.debug(`[classifier] Classifying ${batch.length} unknown tools via GPT...`);

    try {
      const { content } = await complete({
        system: CLASSIFY_SYSTEM,
        messages: [{ role: "user", content: JSON.stringify(names) }],
        temperature: 0.1,
        maxTokens: 2048,
      });

      const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      const classified: ClassifiedTool[] = JSON.parse(clean);

      for (const tool of batch) {
        const match = classified.find((c) => c.name === tool.name);
        if (match) {
          result.push({
            ...tool,
            kind: match.kind,
            github: match.github ?? undefined,
            homepage: match.homepage ?? undefined,
          });
        } else {
          result.push(tool);
        }
      }
    } catch (e) {
      logger.debug(`[classifier] Batch classification failed: ${e}`);
      result.push(...batch);
    }
  }

  return result;
}

/**
 * Classify all detected tools: fast-path from toolmap, GPT fallback for unknowns.
 */
export async function classifyTools(tools: DetectedTool[]): Promise<DetectedTool[]> {
  const known: DetectedTool[] = [];
  const unknown: DetectedTool[] = [];

  for (const tool of tools) {
    const entry = resolveKnownTool(tool.name);
    if (entry) {
      known.push({
        ...tool,
        kind: entry.kind,
        github: entry.github ?? tool.github,
        homepage: entry.advisoryUrl ?? tool.homepage,
      });
    } else {
      unknown.push(tool);
    }
  }

  logger.info(`Tool classification: ${known.length} known, ${unknown.length} need AI classification`);

  const classifiedUnknown = await classifyUnknownTools(unknown);

  return [...known, ...classifiedUnknown];
}
