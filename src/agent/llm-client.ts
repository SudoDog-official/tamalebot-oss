// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * LLM Client
 *
 * Multi-provider LLM client supporting:
 *   - Anthropic Claude (native SDK)
 *   - OpenAI GPT (OpenAI SDK)
 *   - Moonshot Kimi (OpenAI-compatible API)
 *   - Google Gemini (OpenAI-compatible API)
 *   - MiniMax (OpenAI-compatible API)
 *
 * The agent loop uses Anthropic message format internally.
 * OpenAI-compatible providers translate at the boundary.
 */

import Anthropic from "@anthropic-ai/sdk";
import type { Tool, MessageParam, ContentBlockParam } from "@anthropic-ai/sdk/resources/messages.js";
import OpenAI from "openai";

export type LLMProvider = "anthropic" | "openai" | "moonshot" | "google" | "minimax";

export interface LLMConfig {
  apiKey: string;
  provider?: LLMProvider;
  model?: string;
  maxTokens?: number;
  systemPrompt?: string;
}

export interface ToolCallRequest {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface LLMResponse {
  text: string;
  toolCalls: ToolCallRequest[];
  stopReason: string | null;
  inputTokens: number;
  outputTokens: number;
}

/** Detect provider from model name if not explicitly set */
function detectProvider(model: string): LLMProvider {
  if (model.startsWith("claude")) return "anthropic";
  if (model.startsWith("gpt") || model.startsWith("o1") || model.startsWith("o3")) return "openai";
  if (model.startsWith("kimi")) return "moonshot";
  if (model.startsWith("gemini")) return "google";
  if (model.startsWith("minimax")) return "minimax";
  return "anthropic";
}

/** Provider base URLs for OpenAI-compatible APIs */
const PROVIDER_BASE_URLS: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  moonshot: "https://api.moonshot.ai/v1",
  google: "https://generativelanguage.googleapis.com/v1beta/openai",
  minimax: "https://api.minimaxi.chat/v1",
};

const DEFAULT_MODELS: Record<LLMProvider, string> = {
  anthropic: "claude-sonnet-4-5-20250929",
  openai: "gpt-4o",
  moonshot: "kimi-k2.5",
  google: "gemini-2.5-flash",
  minimax: "minimax-m2.5",
};

const DEFAULT_MAX_TOKENS = 4096;

export class LLMClient {
  private provider: LLMProvider;
  private model: string;
  private maxTokens: number;
  private systemPrompt: string;

  private anthropicClient?: Anthropic;
  private openaiClient?: OpenAI;

  constructor(config: LLMConfig) {
    this.provider = config.provider ?? detectProvider(config.model ?? "claude");
    this.model = config.model ?? DEFAULT_MODELS[this.provider];
    this.maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.systemPrompt = config.systemPrompt ?? "";

    if (this.provider === "anthropic") {
      this.anthropicClient = new Anthropic({ apiKey: config.apiKey });
    } else {
      const baseURL = PROVIDER_BASE_URLS[this.provider];
      this.openaiClient = new OpenAI({ apiKey: config.apiKey, baseURL });
    }
  }

  async sendMessage(
    messages: MessageParam[],
    tools: Tool[]
  ): Promise<LLMResponse> {
    if (this.provider === "anthropic") {
      return this.sendAnthropic(messages, tools);
    }
    return this.sendOpenAICompatible(messages, tools);
  }

  // --- Anthropic ---

  private async sendAnthropic(
    messages: MessageParam[],
    tools: Tool[]
  ): Promise<LLMResponse> {
    const response = await this.anthropicClient!.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      system: this.systemPrompt || undefined,
      messages,
      tools: tools.length > 0 ? tools : undefined,
    });

    const text: string[] = [];
    const toolCalls: ToolCallRequest[] = [];

    for (const block of response.content) {
      if (block.type === "text") {
        text.push(block.text);
      } else if (block.type === "tool_use") {
        toolCalls.push({
          id: block.id,
          name: block.name,
          input: block.input as Record<string, unknown>,
        });
      }
    }

    return {
      text: text.join("\n"),
      toolCalls,
      stopReason: response.stop_reason,
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    };
  }

  // --- OpenAI-Compatible (OpenAI, Kimi, Gemini, MiniMax) ---

  /**
   * Convert Anthropic-format messages to OpenAI-format messages.
   * The agent loop stores history in Anthropic format, so we translate here.
   */
  private convertMessages(
    messages: MessageParam[]
  ): OpenAI.Chat.ChatCompletionMessageParam[] {
    const result: OpenAI.Chat.ChatCompletionMessageParam[] = [];

    if (this.systemPrompt) {
      result.push({ role: "system", content: this.systemPrompt });
    }

    for (const msg of messages) {
      if (msg.role === "assistant") {
        if (typeof msg.content === "string") {
          result.push({ role: "assistant", content: msg.content });
        } else if (Array.isArray(msg.content)) {
          let text = "";
          const toolCalls: OpenAI.Chat.ChatCompletionMessageToolCall[] = [];

          for (const block of msg.content) {
            if (typeof block === "object" && "type" in block) {
              if (block.type === "text") {
                text += (block as { type: "text"; text: string }).text;
              } else if (block.type === "tool_use") {
                const tu = block as { type: "tool_use"; id: string; name: string; input: unknown };
                toolCalls.push({
                  id: tu.id,
                  type: "function",
                  function: {
                    name: tu.name,
                    arguments: JSON.stringify(tu.input),
                  },
                });
              }
            }
          }

          if (toolCalls.length > 0) {
            result.push({
              role: "assistant",
              content: text || null,
              tool_calls: toolCalls,
            });
          } else {
            result.push({ role: "assistant", content: text });
          }
        }
      } else if (msg.role === "user") {
        if (typeof msg.content === "string") {
          result.push({ role: "user", content: msg.content });
        } else if (Array.isArray(msg.content)) {
          // Anthropic user messages with tool_result blocks
          for (const block of msg.content) {
            if (typeof block === "object" && "type" in block) {
              const b = block as unknown as Record<string, unknown>;
              if (b.type === "tool_result") {
                result.push({
                  role: "tool",
                  tool_call_id: b.tool_use_id as string,
                  content: b.is_error ? `ERROR: ${b.content}` : (b.content as string),
                });
              }
            }
          }
        }
      }
    }

    return result;
  }

  /**
   * Convert Anthropic tool schemas to OpenAI function tool format.
   */
  private convertTools(
    tools: Tool[]
  ): OpenAI.Chat.ChatCompletionTool[] {
    return tools.map((t) => ({
      type: "function" as const,
      function: {
        name: t.name,
        description: t.description ?? "",
        parameters: t.input_schema as Record<string, unknown>,
      },
    }));
  }

  private async sendOpenAICompatible(
    messages: MessageParam[],
    tools: Tool[]
  ): Promise<LLMResponse> {
    const openaiMessages = this.convertMessages(messages);
    const openaiTools = tools.length > 0 ? this.convertTools(tools) : undefined;

    const response = await this.openaiClient!.chat.completions.create({
      model: this.model,
      max_tokens: this.maxTokens,
      messages: openaiMessages,
      tools: openaiTools,
    });

    const choice = response.choices[0];
    const text = choice.message.content ?? "";
    const toolCalls: ToolCallRequest[] = [];

    if (choice.message.tool_calls) {
      for (const tc of choice.message.tool_calls) {
        if (tc.type === "function") {
          toolCalls.push({
            id: tc.id,
            name: tc.function.name,
            input: JSON.parse(tc.function.arguments || "{}"),
          });
        }
      }
    }

    return {
      text,
      toolCalls,
      stopReason: choice.finish_reason,
      inputTokens: response.usage?.prompt_tokens ?? 0,
      outputTokens: response.usage?.completion_tokens ?? 0,
    };
  }

  buildToolResults(
    results: Array<{ toolCallId: string; output: string; isError?: boolean }>
  ): ContentBlockParam[] {
    return results.map((r) => ({
      type: "tool_result" as const,
      tool_use_id: r.toolCallId,
      content: r.output,
      is_error: r.isError,
    }));
  }

  getModel(): string {
    return this.model;
  }

  getProvider(): LLMProvider {
    return this.provider;
  }
}
