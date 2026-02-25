import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock @slack/bolt before importing
const mockApp = {
  event: vi.fn(),
  start: vi.fn().mockResolvedValue(undefined),
  stop: vi.fn().mockResolvedValue(undefined),
  client: {
    auth: {
      test: vi.fn().mockResolvedValue({ user: "test-bot", user_id: "U123BOT" }),
    },
  },
};

vi.mock("@slack/bolt", () => ({
  App: vi.fn(() => mockApp),
}));

// Mock the agent loop
vi.mock("../../src/agent/agent-loop.js", () => ({
  runAgentLoop: vi.fn().mockResolvedValue({
    text: "Hello from the agent!",
    toolCallCount: 0,
    totalInputTokens: 100,
    totalOutputTokens: 50,
    totalCacheCreationTokens: 0,
    totalCacheReadTokens: 0,
    iterations: 1,
  }),
}));

import { SlackIntegration } from "../../src/integrations/slack.js";
import { runAgentLoop } from "../../src/agent/agent-loop.js";
import type { LLMClient } from "../../src/agent/llm-client.js";
import type { ToolContext } from "../../src/agent/tools.js";

function createMockLLM(): LLMClient {
  return {
    sendMessage: vi.fn(),
    buildToolResults: vi.fn(),
    getModel: () => "mock-model",
    getProvider: () => "anthropic",
  } as unknown as LLMClient;
}

function createMockToolContext(): ToolContext {
  return {
    policy: {} as any,
    audit: { log: vi.fn(), close: vi.fn() } as any,
    agentId: "test-agent",
    workDir: "/tmp",
  };
}

describe("SlackIntegration", () => {
  let slack: SlackIntegration;
  let llm: LLMClient;
  let toolContext: ToolContext;

  beforeEach(() => {
    vi.clearAllMocks();
    llm = createMockLLM();
    toolContext = createMockToolContext();
    slack = new SlackIntegration({
      botToken: "xoxb-test",
      appToken: "xapp-test",
      llm,
      toolContext,
    });
  });

  it("should have correct name", () => {
    expect(slack.name).toBe("slack");
  });

  it("should not be connected initially", () => {
    expect(slack.isConnected()).toBe(false);
  });

  it("should connect via Socket Mode", async () => {
    await slack.connect();
    expect(mockApp.start).toHaveBeenCalled();
    expect(mockApp.client.auth.test).toHaveBeenCalled();
    expect(slack.isConnected()).toBe(true);
  });

  it("should register app_mention and message event handlers", async () => {
    await slack.connect();
    expect(mockApp.event).toHaveBeenCalledWith("app_mention", expect.any(Function));
    expect(mockApp.event).toHaveBeenCalledWith("message", expect.any(Function));
  });

  it("should disconnect cleanly", async () => {
    await slack.connect();
    await slack.disconnect();
    expect(mockApp.stop).toHaveBeenCalled();
    expect(slack.isConnected()).toBe(false);
  });

  describe("message handling", () => {
    let mentionHandler: (args: any) => Promise<void>;
    let messageHandler: (args: any) => Promise<void>;

    beforeEach(async () => {
      await slack.connect();
      // Extract the registered event handlers
      const calls = mockApp.event.mock.calls;
      mentionHandler = calls.find((c: any[]) => c[0] === "app_mention")![1];
      messageHandler = calls.find((c: any[]) => c[0] === "message")![1];
    });

    it("should handle app mentions and call runAgentLoop", async () => {
      const say = vi.fn().mockResolvedValue(undefined);
      await mentionHandler({
        event: {
          text: "<@U123BOT> hello",
          user: "U456USER",
          channel: "C789",
          team: "T111",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(runAgentLoop).toHaveBeenCalledWith(
        "hello",
        expect.any(Array),
        expect.objectContaining({ llm, toolContext })
      );
      expect(say).toHaveBeenCalledWith(
        expect.objectContaining({ text: "Hello from the agent!" })
      );
    });

    it("should ignore bot messages", async () => {
      const say = vi.fn();
      await mentionHandler({
        event: {
          text: "hello",
          bot_id: "B123",
          channel: "C789",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(runAgentLoop).not.toHaveBeenCalled();
      expect(say).not.toHaveBeenCalled();
    });

    it("should handle /clear command", async () => {
      const say = vi.fn().mockResolvedValue(undefined);
      await mentionHandler({
        event: {
          text: "<@U123BOT> /clear",
          user: "U456USER",
          channel: "C789",
          team: "T111",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(say).toHaveBeenCalledWith(
        expect.objectContaining({ text: "Conversation cleared." })
      );
      expect(runAgentLoop).not.toHaveBeenCalled();
    });

    it("should handle /status command", async () => {
      const say = vi.fn().mockResolvedValue(undefined);
      await mentionHandler({
        event: {
          text: "<@U123BOT> /status",
          user: "U456USER",
          channel: "C789",
          team: "T111",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(say).toHaveBeenCalledWith(
        expect.objectContaining({
          text: expect.stringContaining("Agent: test-agent"),
        })
      );
      expect(runAgentLoop).not.toHaveBeenCalled();
    });

    it("should only handle DMs in message event", async () => {
      const say = vi.fn().mockResolvedValue(undefined);

      // Non-DM should be ignored
      await messageHandler({
        event: {
          text: "hello",
          user: "U456USER",
          channel: "C789",
          channel_type: "channel",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(runAgentLoop).not.toHaveBeenCalled();

      // DM should be processed
      await messageHandler({
        event: {
          text: "hello",
          user: "U456USER",
          channel: "D789",
          channel_type: "im",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(runAgentLoop).toHaveBeenCalled();
    });
  });

  describe("channel allowlist", () => {
    it("should respect allowedChannelIds", async () => {
      const restrictedSlack = new SlackIntegration({
        botToken: "xoxb-test",
        appToken: "xapp-test",
        llm,
        toolContext,
        allowedChannelIds: ["C_ALLOWED"],
      });

      await restrictedSlack.connect();
      const mentionHandler = mockApp.event.mock.calls.find(
        (c: any[]) => c[0] === "app_mention"
      )![1];

      const say = vi.fn().mockResolvedValue(undefined);

      // Unauthorized channel
      await mentionHandler({
        event: {
          text: "<@U123BOT> hello",
          user: "U456USER",
          channel: "C_NOTALLOWED",
          team: "T111",
          ts: "1234567890.123456",
        },
        say,
      });

      expect(runAgentLoop).not.toHaveBeenCalled();
    });
  });
});
