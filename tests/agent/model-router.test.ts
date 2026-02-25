import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the LLMClient constructor
vi.mock("../../src/agent/llm-client.js", () => {
  return {
    LLMClient: vi.fn().mockImplementation((config: any) => ({
      sendMessage: vi.fn().mockResolvedValue({
        text: config.systemPrompt?.includes("classifier") ? "SIMPLE" : "response",
        toolCalls: [],
        stopReason: "end_turn",
        inputTokens: 50,
        outputTokens: 5,
        cacheCreationTokens: 0,
        cacheReadTokens: 0,
      }),
      getModel: () => config.model ?? "mock-model",
      getProvider: () => config.provider ?? "anthropic",
    })),
  };
});

import { ModelRouter, type RouteClassification } from "../../src/agent/model-router.js";
import { LLMClient } from "../../src/agent/llm-client.js";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";

describe("ModelRouter", () => {
  let primaryLLM: LLMClient;
  let router: ModelRouter;

  beforeEach(() => {
    vi.clearAllMocks();

    primaryLLM = {
      sendMessage: vi.fn(),
      getModel: () => "claude-sonnet-4-5-20250929",
      getProvider: () => "anthropic",
    } as unknown as LLMClient;

    router = new ModelRouter({
      primaryLLM,
      routerModel: "claude-haiku-4-5-20251001",
      apiKey: "test-key",
      provider: "anthropic",
      systemPrompt: "You are a helpful agent.",
    });
  });

  it("should create separate LLM instances", () => {
    // LLMClient constructor should be called twice: cheapLLM and classifierLLM
    expect(LLMClient).toHaveBeenCalledTimes(2);
  });

  it("should classify and route to cheap model for simple messages", async () => {
    const history: MessageParam[] = [];
    const result = await router.route("hello", history);

    expect(result.classification).toBe("SIMPLE");
    expect(result.routerTokens.input).toBeGreaterThanOrEqual(0);
    expect(result.routerTokens.output).toBeGreaterThanOrEqual(0);
    // The cheap LLM should be returned
    expect(result.llm.getModel()).toBe("claude-haiku-4-5-20251001");
  });

  it("should route to primary model for complex messages", async () => {
    // Override classifier to return COMPLEX
    const classifierInstances = (LLMClient as any).mock.results;
    const classifierInstance = classifierInstances[classifierInstances.length - 1].value;
    classifierInstance.sendMessage.mockResolvedValueOnce({
      text: "COMPLEX",
      toolCalls: [],
      stopReason: "end_turn",
      inputTokens: 60,
      outputTokens: 5,
      cacheCreationTokens: 0,
      cacheReadTokens: 0,
    });

    const history: MessageParam[] = [];
    const result = await router.route(
      "Write a Python script that processes CSV files and generates charts",
      history
    );

    expect(result.classification).toBe("COMPLEX");
    // Primary LLM should be returned
    expect(result.llm).toBe(primaryLLM);
  });

  it("should default to primary model on classification failure", async () => {
    // Override classifier to throw
    const classifierInstances = (LLMClient as any).mock.results;
    const classifierInstance = classifierInstances[classifierInstances.length - 1].value;
    classifierInstance.sendMessage.mockRejectedValueOnce(new Error("API error"));

    const history: MessageParam[] = [];
    const result = await router.route("hello", history);

    expect(result.classification).toBe("COMPLEX");
    expect(result.llm).toBe(primaryLLM);
    expect(result.routerTokens.input).toBe(0);
    expect(result.routerTokens.output).toBe(0);
  });

  it("should track routing stats", async () => {
    const history: MessageParam[] = [];

    // Route a few messages
    await router.route("hello", history);
    await router.route("hi there", history);

    // Override to return COMPLEX for next
    const classifierInstances = (LLMClient as any).mock.results;
    const classifierInstance = classifierInstances[classifierInstances.length - 1].value;
    classifierInstance.sendMessage.mockResolvedValueOnce({
      text: "COMPLEX",
      toolCalls: [],
      stopReason: "end_turn",
      inputTokens: 60,
      outputTokens: 5,
      cacheCreationTokens: 0,
      cacheReadTokens: 0,
    });
    await router.route("analyze this data", history);

    const stats = router.getStats();
    expect(stats.totalRouted).toBe(3);
    expect(stats.simple).toBe(2);
    expect(stats.complex).toBe(1);
    expect(stats.savingsPercent).toBe(67); // 2/3 = 67%
  });

  it("should capture router tokens", async () => {
    const history: MessageParam[] = [];
    const result = await router.route("hello", history);

    expect(result.routerTokens).toBeDefined();
    expect(typeof result.routerTokens.input).toBe("number");
    expect(typeof result.routerTokens.output).toBe("number");
  });
});
