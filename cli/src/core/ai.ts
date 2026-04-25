import OpenAI from "openai";
import type { ChatCompletionMessageParam, ChatCompletionTool } from "openai/resources/chat/completions";
import { logger } from "./logger.js";

let _client: OpenAI | null = null;

export function getOpenAI(apiKey?: string): OpenAI {
  if (!_client) {
    const key = apiKey ?? process.env["OPENAI_API_KEY"];
    if (!key) {
      throw new Error(
        "OPENAI_API_KEY is not set. Export it or add it to breachscope.yaml under ai.openaiApiKey."
      );
    }
    _client = new OpenAI({ apiKey: key });
  }
  return _client;
}

export const AI_MODEL = "gpt-4o";

export interface CompletionOptions {
  system: string;
  messages: ChatCompletionMessageParam[];
  tools?: ChatCompletionTool[];
  temperature?: number;
  maxTokens?: number;
  maxIterations?: number;
}

export interface CompletionResult {
  content: string;
  toolCalls: Array<{ id: string; name: string; args: Record<string, unknown> }>;
  tokensUsed: number;
}

export async function complete(opts: CompletionOptions): Promise<CompletionResult> {
  const client = getOpenAI();

  const messages: ChatCompletionMessageParam[] = [
    { role: "system", content: opts.system },
    ...opts.messages,
  ];

  const response = await client.chat.completions.create({
    model: AI_MODEL,
    messages,
    tools: opts.tools,
    tool_choice: opts.tools?.length ? "auto" : undefined,
    temperature: opts.temperature ?? 0.2,
    max_tokens: opts.maxTokens ?? 4096,
  });

  const choice = response.choices[0]!;
  const toolCalls = (choice.message.tool_calls ?? []).map((tc) => ({
    id: tc.id,
    name: tc.function.name,
    args: JSON.parse(tc.function.arguments) as Record<string, unknown>,
  }));

  logger.debug(
    `[ai] ${AI_MODEL} — ${response.usage?.total_tokens ?? "?"} tokens`,
    toolCalls.length ? `| ${toolCalls.length} tool call(s)` : ""
  );

  return {
    content: choice.message.content ?? "",
    toolCalls,
    tokensUsed: response.usage?.total_tokens ?? 0,
  };
}

/** Run an agentic loop: call → execute tools → call again until no tool calls remain. */
export async function agentLoop(
  opts: CompletionOptions,
  executeTool: (name: string, args: Record<string, unknown>) => Promise<string>
): Promise<{ content: string; tokensUsed: number }> {
  const messages: ChatCompletionMessageParam[] = [...opts.messages];
  let totalTokens = 0;
  let iterations = 0;

  const maxIterations = opts.maxIterations ?? 10;
  while (iterations < maxIterations) {
    iterations++;
    const result = await complete({ ...opts, messages });
    totalTokens += result.tokensUsed;

    if (result.toolCalls.length === 0) {
      return { content: result.content, tokensUsed: totalTokens };
    }

    // Add assistant turn with tool calls
    messages.push({
      role: "assistant",
      content: result.content,
      tool_calls: result.toolCalls.map((tc) => ({
        id: tc.id,
        type: "function" as const,
        function: { name: tc.name, arguments: JSON.stringify(tc.args) },
      })),
    });

    // Execute tools and collect results
    for (const tc of result.toolCalls) {
      logger.debug(`[tool] ${tc.name}(${JSON.stringify(tc.args).slice(0, 80)}...)`);
      let toolResult: string;
      try {
        toolResult = await executeTool(tc.name, tc.args);
      } catch (e) {
        toolResult = `Error: ${String(e)}`;
      }
      messages.push({ role: "tool", tool_call_id: tc.id, content: toolResult });
    }
  }

  return { content: "Max iterations reached.", tokensUsed: totalTokens };
}
