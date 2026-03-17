// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Mock LLM Client
 *
 * A drop-in replacement for LLMClient that returns canned responses.
 * Enables full agent testing without API keys or network access.
 *
 * Usage:
 *   TAMALEBOT_MOCK_LLM=true npx tsx src/agent/index.ts
 *
 * The mock LLM echoes user messages and responds to common patterns
 * (greetings, tool requests, etc.) with realistic-looking responses.
 */

import type { MessageParam, Tool, ContentBlockParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMResponse, ToolCallRequest } from "./llm-client.js";

export class MockLLMClient {
  private model = "mock-model";
  private systemPrompt: string;
  private callCount = 0;

  constructor(opts?: { systemPrompt?: string; model?: string }) {
    this.systemPrompt = opts?.systemPrompt ?? "";
    if (opts?.model) this.model = opts.model;
  }

  async sendMessage(
    messages: MessageParam[],
    tools: Tool[]
  ): Promise<LLMResponse> {
    this.callCount++;

    // Get the last user message text
    const lastUserMsg = this.extractLastUserText(messages);

    // Check if this is a tool result follow-up (just respond with text)
    if (this.isToolResultFollowUp(messages)) {
      return this.textResponse(
        `Done. I executed the requested action successfully. Here's a summary of what happened.`
      );
    }

    // Pattern-match on user input for realistic responses
    const lower = lastUserMsg.toLowerCase();

    // Greeting
    if (/^(hi|hello|hey|howdy|greetings)/i.test(lower)) {
      return this.textResponse(
        `Hello! I'm a TamaleBot agent running in mock mode. I can simulate tool calls and responses. How can I help?`
      );
    }

    // Health/status check
    if (lower.includes("status") || lower.includes("health") || lower.includes("alive")) {
      return this.textResponse(
        `I'm running in mock mode. All systems operational. Call count: ${this.callCount}.`
      );
    }

    // File read request → simulate tool call
    if (lower.includes("read") && lower.includes("file") && tools.some(t => t.name === "file_read")) {
      return this.toolCallResponse("Let me read that file for you.", [{
        id: `mock_tool_${this.callCount}`,
        name: "file_read",
        input: { path: "/tmp/workspace/test.txt" },
      }]);
    }

    // Shell command request → simulate tool call
    if ((lower.includes("run") || lower.includes("execute") || lower.includes("shell")) &&
        tools.some(t => t.name === "shell")) {
      const cmd = lower.includes("ls") ? "ls -la" : "echo 'mock command executed'";
      return this.toolCallResponse("I'll run that command.", [{
        id: `mock_tool_${this.callCount}`,
        name: "shell",
        input: { command: cmd },
      }]);
    }

    // Web browse request
    if ((lower.includes("browse") || lower.includes("fetch") || lower.includes("url")) &&
        tools.some(t => t.name === "web_browse")) {
      return this.toolCallResponse("Let me fetch that page.", [{
        id: `mock_tool_${this.callCount}`,
        name: "web_browse",
        input: { url: "https://example.com" },
      }]);
    }

    // Default: echo with acknowledgment
    return this.textResponse(
      `[Mock LLM] Received your message: "${lastUserMsg.slice(0, 200)}". ` +
      `I have ${tools.length} tools available. ` +
      `This is mock response #${this.callCount}.`
    );
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

  getProvider(): string {
    return "mock";
  }

  // --- Helpers ---

  private textResponse(text: string): LLMResponse {
    return {
      text,
      toolCalls: [],
      stopReason: "end_turn",
      inputTokens: 100,
      outputTokens: Math.ceil(text.length / 4),
      cacheCreationTokens: 0,
      cacheReadTokens: 0,
    };
  }

  private toolCallResponse(text: string, toolCalls: ToolCallRequest[]): LLMResponse {
    return {
      text,
      toolCalls,
      stopReason: "tool_use",
      inputTokens: 150,
      outputTokens: Math.ceil(text.length / 4) + 50,
      cacheCreationTokens: 0,
      cacheReadTokens: 0,
    };
  }

  private extractLastUserText(messages: MessageParam[]): string {
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      if (msg.role === "user") {
        if (typeof msg.content === "string") return msg.content;
        if (Array.isArray(msg.content)) {
          // Skip tool_result arrays, look for text
          for (const block of msg.content) {
            if (typeof block === "object" && "type" in block) {
              const b = block as unknown as Record<string, unknown>;
              if (b.type === "text") return b.text as string;
            }
          }
        }
      }
    }
    return "";
  }

  private isToolResultFollowUp(messages: MessageParam[]): boolean {
    if (messages.length < 2) return false;
    const last = messages[messages.length - 1];
    if (last.role !== "user" || !Array.isArray(last.content)) return false;
    return (last.content as unknown as Array<Record<string, unknown>>).some(
      b => typeof b === "object" && "type" in b && b.type === "tool_result"
    );
  }
}
