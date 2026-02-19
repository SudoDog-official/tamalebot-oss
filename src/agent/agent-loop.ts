// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Agent Loop
 *
 * The core think/act cycle:
 *   1. Send user message + conversation history to LLM
 *   2. LLM responds with text and/or tool calls
 *   3. Execute each tool call (with policy checks)
 *   4. Send tool results back to LLM
 *   5. Repeat until LLM responds with text only (no more tool calls)
 *   6. Return final text response
 *
 * This is the beating heart of every TamaleBot agent.
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient, LLMResponse } from "./llm-client.js";
import { TOOL_SCHEMAS, executeTool, type ToolContext } from "./tools.js";

export interface AgentLoopConfig {
  llm: LLMClient;
  toolContext: ToolContext;
  maxIterations?: number;
  onToolCall?: (name: string, input: Record<string, unknown>) => void;
  onToolResult?: (name: string, output: string, isError: boolean) => void;
  onText?: (text: string) => void;
  onTokenUsage?: (input: number, output: number) => void;
}

export interface AgentResponse {
  text: string;
  toolCallCount: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  iterations: number;
}

const DEFAULT_MAX_ITERATIONS = 20;

/**
 * Run the agent loop for a single user message.
 * Maintains the conversation history across calls.
 */
export async function runAgentLoop(
  userMessage: string,
  conversationHistory: MessageParam[],
  config: AgentLoopConfig
): Promise<AgentResponse> {
  const { llm, toolContext, onToolCall, onToolResult, onText, onTokenUsage } = config;
  const maxIter = config.maxIterations ?? DEFAULT_MAX_ITERATIONS;

  // Add user message to history
  conversationHistory.push({ role: "user", content: userMessage });

  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let toolCallCount = 0;
  let iterations = 0;
  let finalText = "";

  for (let i = 0; i < maxIter; i++) {
    iterations++;

    // Send to LLM
    const response: LLMResponse = await llm.sendMessage(
      conversationHistory,
      TOOL_SCHEMAS
    );

    totalInputTokens += response.inputTokens;
    totalOutputTokens += response.outputTokens;
    onTokenUsage?.(response.inputTokens, response.outputTokens);

    // If there's text, capture it
    if (response.text) {
      finalText = response.text;
      onText?.(response.text);
    }

    // If no tool calls, the agent is done thinking
    if (response.toolCalls.length === 0) {
      // Add assistant response to history
      conversationHistory.push({ role: "assistant", content: response.text });
      break;
    }

    // Build the assistant message with both text and tool_use blocks
    const assistantContent: Array<
      | { type: "text"; text: string }
      | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
    > = [];

    if (response.text) {
      assistantContent.push({ type: "text", text: response.text });
    }

    for (const tc of response.toolCalls) {
      assistantContent.push({
        type: "tool_use",
        id: tc.id,
        name: tc.name,
        input: tc.input,
      });
    }

    conversationHistory.push({ role: "assistant", content: assistantContent });

    // Execute each tool call
    const toolResults: Array<{
      type: "tool_result";
      tool_use_id: string;
      content: string;
      is_error?: boolean;
    }> = [];

    for (const tc of response.toolCalls) {
      toolCallCount++;
      onToolCall?.(tc.name, tc.input);

      const result = await executeTool(tc.name, tc.input, toolContext);
      onToolResult?.(tc.name, result.output, result.isError);

      toolResults.push({
        type: "tool_result",
        tool_use_id: tc.id,
        content: result.output,
        is_error: result.isError || undefined,
      });
    }

    // Send tool results back
    conversationHistory.push({ role: "user", content: toolResults });
  }

  return {
    text: finalText,
    toolCallCount,
    totalInputTokens,
    totalOutputTokens,
    iterations,
  };
}
