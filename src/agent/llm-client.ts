// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * LLM Client
 *
 * Handles communication with the Anthropic Claude API.
 * Supports tool-use (function calling) and streaming responses.
 * Claude-first by design — OpenAI support can be added later.
 */

import Anthropic from "@anthropic-ai/sdk";
import type { Tool, MessageParam, ContentBlockParam } from "@anthropic-ai/sdk/resources/messages.js";

export interface LLMConfig {
  apiKey: string;
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

const DEFAULT_MODEL = "claude-sonnet-4-5-20250929";
const DEFAULT_MAX_TOKENS = 4096;

export class LLMClient {
  private client: Anthropic;
  private model: string;
  private maxTokens: number;
  private systemPrompt: string;

  constructor(config: LLMConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model ?? DEFAULT_MODEL;
    this.maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.systemPrompt = config.systemPrompt ?? "";
  }

  async sendMessage(
    messages: MessageParam[],
    tools: Tool[]
  ): Promise<LLMResponse> {
    const response = await this.client.messages.create({
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

  /**
   * Build tool result content blocks to send back to the LLM
   * after executing tool calls.
   */
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
}
