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

export const AI_MODEL = "gpt-4.1";

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

/** Prune tool result messages from the middle to recover from context overflow.
 *  Keeps the original user message and the most recent exchanges intact. */
function pruneToolResults(messages: ChatCompletionMessageParam[], keepTail = 6): ChatCompletionMessageParam[] {
  const first = messages[0]!; // original user message
  const tail = messages.slice(-keepTail);
  // Make sure we don't duplicate the first message
  const tailHasFirst = tail.some((m) => m === first);
  return tailHasFirst ? tail : [first, ...tail];
}

function isContextLengthError(e: unknown): boolean {
  if (e instanceof Error) {
    const msg = e.message.toLowerCase();
    return msg.includes("context_length_exceeded") || msg.includes("maximum context length") || msg.includes("reduce the length");
  }
  return false;
}

/** Run an agentic loop: call → execute tools → call again until no tool calls remain.
 *  On context overflow: prune old tool results and retry rather than crashing. */
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

    let result;
    try {
      result = await complete({ ...opts, messages });
    } catch (e) {
      if (isContextLengthError(e)) {
        // Drop old tool results, keep first user message + recent tail, then retry once
        logger.debug(`[ai] Context overflow — pruning history (${messages.length} → pruned) and retrying`);
        const pruned = pruneToolResults(messages, 8);
        try {
          result = await complete({ ...opts, messages: pruned });
          // If recovery worked, replace our working messages with pruned
          messages.splice(0, messages.length, ...pruned);
        } catch (e2) {
          if (isContextLengthError(e2)) {
            // One final attempt with only the original user message
            logger.debug(`[ai] Context still too large — retrying with minimal history`);
            const minimal = [messages[0]!];
            result = await complete({ ...opts, messages: minimal });
            messages.splice(0, messages.length, ...minimal);
          } else {
            throw e2;
          }
        }
      } else {
        throw e;
      }
    }

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
