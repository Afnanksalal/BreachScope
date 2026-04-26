import { agentLoop } from "../core/ai.js";
import { webSearch } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

export interface SpecialistTask {
  attack_type: string;
  priority: "critical" | "high" | "medium" | "low";
  context: string;
  rationale: string;
  estimated_impact: string;
  target_endpoints?: string[];
  credentials_to_use?: string[];
}

interface SupervisorPlan {
  tasks: SpecialistTask[];
  attack_narrative: string;
  highest_value_target: string;
}

const SUPERVISOR_SYSTEM = `You are a senior red team supervisor with 15 years of offensive security experience.

Your job: Analyze the recon data from an initial application scan and create a precise, prioritized attack plan for specialist agents.

You have read the entire recon output — env vars, open ports, services, endpoints, source code patterns, auth mechanisms, framework versions, credential keys.

Your output must be:
1. Targeted — give each specialist EXACT context: endpoint paths, parameter names, credential values, source code snippets
2. Prioritized — critical impact paths first (DB dump, admin access, RCE)
3. Chained — identify how findings can be COMBINED (e.g. CORS + auth token theft, SSRF + internal service access)
4. Zero fluff — every task must have a concrete hypothesis and exact target

Specialist types available:
- sql_injection: Test SQL injection in endpoints and parameters
- jwt_attack: Crack or forge JWT tokens
- auth_bypass: Bypass authentication, IDOR, mass assignment
- ssrf: Server-side request forgery via URL parameters
- xss: Cross-site scripting in input reflection points
- file_traversal: Path traversal in file-serving endpoints
- redis_exploit: Exploit unauthenticated Redis, read sessions
- prototype_pollution: Prototype pollution via deep object merge
- race_condition: Race conditions in financial/state operations
- business_logic: Business logic flaws in pricing, permissions, workflows
- ai_llm_attacks: Prompt injection, jailbreak, AI system extraction

Think like a real attacker: What's the shortest path to CRITICAL impact? DB dump? Admin access? RCE? Token theft?

Use web_search if you see a specific framework version or tech stack and want to confirm known CVEs or attack techniques before assigning tasks.`;

const SUPERVISOR_TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for known vulnerabilities, CVEs, or attack techniques for the specific framework/version identified in the recon data. Use to confirm exploit viability before assigning a specialist.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Specific query: framework version + exploit technique" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "create_attack_plan",
      description: "Submit the prioritized attack plan. Call once after analyzing the recon data and optionally searching for known exploits.",
      parameters: {
        type: "object",
        properties: {
          attack_narrative: {
            type: "string",
            description: "2-3 sentence summary of the highest-impact attack path you identified. What's the crown jewel and how do you get there?",
          },
          highest_value_target: {
            type: "string",
            description: "The single most valuable thing to compromise: 'PostgreSQL users table', 'Admin JWT', 'Redis session store', etc.",
          },
          tasks: {
            type: "array",
            description: "Ordered list of specialist tasks, highest priority first",
            items: {
              type: "object",
              properties: {
                attack_type: {
                  type: "string",
                  enum: [
                    "sql_injection", "jwt_attack", "auth_bypass", "ssrf",
                    "xss", "file_traversal", "redis_exploit", "prototype_pollution",
                    "race_condition", "business_logic", "ai_llm_attacks",
                  ],
                },
                priority: { type: "string", enum: ["critical", "high", "medium", "low"] },
                context: {
                  type: "string",
                  description: "EXACT intel for the specialist: endpoint paths, parameter names, credential values, source code snippets, specific hypothesis to test. The specialist sees NOTHING else — be exhaustive.",
                },
                rationale: {
                  type: "string",
                  description: "Why this attack? What evidence in the recon suggests it's viable?",
                },
                estimated_impact: {
                  type: "string",
                  description: "What's the worst-case outcome if this succeeds? Be specific.",
                },
                target_endpoints: {
                  type: "array",
                  items: { type: "string" },
                  description: "Specific endpoint paths to test",
                },
                credentials_to_use: {
                  type: "array",
                  items: { type: "string" },
                  description: "Credential key=value pairs the specialist should use",
                },
              },
              required: ["attack_type", "priority", "context", "rationale", "estimated_impact"],
            },
          },
        },
        required: ["attack_narrative", "highest_value_target", "tasks"],
      },
    },
  },
];

export async function runSupervisor(
  reconSummary: string,
  projectType: string,
  baseUrl: string,
  discoveredCredentials: Record<string, string>,
  discoveredEndpoints: string[],
  openPorts: number[],
): Promise<SupervisorPlan> {
  let plan: SupervisorPlan = {
    tasks: [],
    attack_narrative: "",
    highest_value_target: "",
  };

  const credsSummary = Object.entries(discoveredCredentials)
    .slice(0, 20)
    .map(([k, v]) => `  ${k}=${v.slice(0, 60)}`)
    .join("\n");

  const userMessage = `RECON COMPLETE — ANALYZE AND CREATE ATTACK PLAN

Target: ${baseUrl}
Project type: ${projectType}
Open ports: ${openPorts.join(", ") || "unknown — assume standard ports"}

DISCOVERED CREDENTIALS (${Object.keys(discoveredCredentials).length} total):
${credsSummary || "  None extracted yet"}

DISCOVERED ENDPOINTS (${discoveredEndpoints.length}):
${discoveredEndpoints.slice(0, 40).map((e) => `  ${e}`).join("\n") || "  None yet — standard REST API assumed"}

RECON SUMMARY:
${reconSummary.slice(0, 3000)}

ANALYSIS INSTRUCTIONS:
1. Identify the HIGHEST IMPACT attack paths based on this specific data
2. Look for: JWT secrets in credentials → jwt_attack; SQL databases with creds → sql_injection + direct DB access; Redis open → redis_exploit; URL/webhook params → ssrf; Text inputs → xss
3. If you see a specific framework version (e.g., Express 4.18, Django 3.2), web_search for known CVEs
4. Chain attacks: DB creds + SQL endpoint = dump user table; JWT secret + admin endpoint = privilege escalation
5. Only assign attack types where you have real evidence — no speculative tasks
6. Maximum 6 tasks — quality over quantity. Each task must have EXACT context.

Call create_attack_plan with your analysis.`;

  try {
    await agentLoop(
      {
        system: SUPERVISOR_SYSTEM,
        messages: [{ role: "user", content: userMessage }],
        tools: SUPERVISOR_TOOLS,
        temperature: 0.05,
        maxTokens: 8192,
        maxIterations: 8,
      },
      async (toolName, args) => {
        if (toolName === "web_search") {
          const q = String(args["query"] ?? "");
          logger.debug(`[supervisor] search: ${q}`);
          return webSearch(q, 6);
        }
        if (toolName === "create_attack_plan") {
          const a = args as Record<string, unknown>;
          plan = {
            attack_narrative: String(a["attack_narrative"] ?? ""),
            highest_value_target: String(a["highest_value_target"] ?? ""),
            tasks: (a["tasks"] as SpecialistTask[] | undefined) ?? [],
          };
          logger.debug(`[supervisor] Plan created: ${plan.tasks.length} tasks, target: ${plan.highest_value_target}`);
          return JSON.stringify({ success: true, tasks_created: plan.tasks.length });
        }
        return "Unknown tool";
      }
    );
  } catch (e) {
    logger.debug(`[supervisor] Error: ${e}`);
  }

  return plan;
}
