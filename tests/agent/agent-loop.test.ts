// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { MessageParam, Tool } from "@anthropic-ai/sdk/resources/messages.js";
import { runAgentLoop, type AgentLoopConfig } from "../../src/agent/agent-loop.js";
import type { LLMClient, LLMResponse } from "../../src/agent/llm-client.js";
import { PolicyEngine } from "../../src/security/policy-engine.js";
import { AuditTrail } from "../../src/security/audit-trail.js";
import type { ToolContext } from "../../src/agent/tools.js";

/**
 * Create a mock LLM client that returns predefined responses.
 */
function createMockLLM(responses: LLMResponse[]): LLMClient {
  let callIndex = 0;
  return {
    sendMessage: vi.fn(async () => {
      if (callIndex >= responses.length) {
        throw new Error("Mock LLM ran out of responses");
      }
      return responses[callIndex++];
    }),
    buildToolResults: vi.fn((results) =>
      results.map((r: { toolCallId: string; output: string; isError?: boolean }) => ({
        type: "tool_result" as const,
        tool_use_id: r.toolCallId,
        content: r.output,
        is_error: r.isError,
      }))
    ),
    getModel: () => "mock-model",
  } as unknown as LLMClient;
}

describe("Agent Loop", () => {
  let testDir: string;
  let toolContext: ToolContext;

  beforeEach(async () => {
    testDir = join(tmpdir(), `tamalebot-loop-test-${Date.now()}`);
    await mkdir(testDir, { recursive: true });

    const logDir = join(testDir, "logs");
    toolContext = {
      policy: new PolicyEngine(),
      audit: new AuditTrail(logDir, "test-agent"),
      agentId: "test-agent",
      workDir: testDir,
    };
  });

  afterEach(async () => {
    toolContext.audit.close();
    await rm(testDir, { recursive: true, force: true });
  });

  it("should return text response when no tools are called", async () => {
    const mockLLM = createMockLLM([
      {
        text: "Hello! How can I help?",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 100,
        outputTokens: 20,
      },
    ]);

    const history: MessageParam[] = [];
    const result = await runAgentLoop("Hi there", history, {
      llm: mockLLM,
      toolContext,
    });

    expect(result.text).toBe("Hello! How can I help?");
    expect(result.toolCallCount).toBe(0);
    expect(result.iterations).toBe(1);
    expect(result.totalInputTokens).toBe(100);
    expect(result.totalOutputTokens).toBe(20);
  });

  it("should execute tool calls and loop back", async () => {
    const mockLLM = createMockLLM([
      // First response: call a tool
      {
        text: "Let me check that for you.",
        toolCalls: [
          {
            id: "tool_1",
            name: "shell",
            input: { command: "echo hello" },
          },
        ],
        stopReason: "tool_use",
        inputTokens: 150,
        outputTokens: 50,
      },
      // Second response: final text
      {
        text: "The command output was: hello",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 200,
        outputTokens: 30,
      },
    ]);

    const history: MessageParam[] = [];
    const result = await runAgentLoop("Run echo hello", history, {
      llm: mockLLM,
      toolContext,
    });

    expect(result.text).toBe("The command output was: hello");
    expect(result.toolCallCount).toBe(1);
    expect(result.iterations).toBe(2);
    expect(result.totalInputTokens).toBe(350);
    expect(result.totalOutputTokens).toBe(80);
  });

  it("should call onToolCall and onToolResult callbacks", async () => {
    const toolCalls: string[] = [];
    const toolResults: string[] = [];

    const mockLLM = createMockLLM([
      {
        text: "",
        toolCalls: [
          { id: "tool_1", name: "shell", input: { command: "echo test" } },
        ],
        stopReason: "tool_use",
        inputTokens: 100,
        outputTokens: 30,
      },
      {
        text: "Done.",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 150,
        outputTokens: 10,
      },
    ]);

    const history: MessageParam[] = [];
    await runAgentLoop("test", history, {
      llm: mockLLM,
      toolContext,
      onToolCall(name) {
        toolCalls.push(name);
      },
      onToolResult(name, output, isError) {
        toolResults.push(`${name}:${isError ? "error" : "ok"}`);
      },
    });

    expect(toolCalls).toEqual(["shell"]);
    expect(toolResults).toEqual(["shell:ok"]);
  });

  it("should handle blocked tool calls", async () => {
    const mockLLM = createMockLLM([
      {
        text: "Let me delete everything.",
        toolCalls: [
          { id: "tool_1", name: "shell", input: { command: "rm -rf /" } },
        ],
        stopReason: "tool_use",
        inputTokens: 100,
        outputTokens: 30,
      },
      {
        text: "That command was blocked by security policy.",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 200,
        outputTokens: 20,
      },
    ]);

    const toolResults: Array<{ name: string; isError: boolean }> = [];
    const history: MessageParam[] = [];

    await runAgentLoop("delete everything", history, {
      llm: mockLLM,
      toolContext,
      onToolResult(name, _output, isError) {
        toolResults.push({ name, isError });
      },
    });

    expect(toolResults[0].isError).toBe(true);
  });

  it("should maintain conversation history", async () => {
    const mockLLM = createMockLLM([
      {
        text: "First response",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 50,
        outputTokens: 10,
      },
    ]);

    const history: MessageParam[] = [];
    await runAgentLoop("First message", history, {
      llm: mockLLM,
      toolContext,
    });

    // History should contain user message + assistant response
    expect(history.length).toBe(2);
    expect(history[0].role).toBe("user");
    expect(history[1].role).toBe("assistant");
  });

  it("should respect max iterations", async () => {
    // Create an LLM that always wants to call tools (infinite loop scenario)
    let callCount = 0;
    const mockLLM = {
      sendMessage: vi.fn(async () => {
        callCount++;
        return {
          text: `Iteration ${callCount}`,
          toolCalls: [
            { id: `tool_${callCount}`, name: "shell", input: { command: "echo loop" } },
          ],
          stopReason: "tool_use",
          inputTokens: 50,
          outputTokens: 20,
        };
      }),
      getModel: () => "mock-model",
    } as unknown as LLMClient;

    const history: MessageParam[] = [];
    const result = await runAgentLoop("infinite loop test", history, {
      llm: mockLLM,
      toolContext,
      maxIterations: 3,
    });

    expect(result.iterations).toBe(3);
    expect(result.toolCallCount).toBe(3);
  });
});
