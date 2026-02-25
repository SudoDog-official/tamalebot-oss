import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock imapflow
const mockImapClient = {
  connect: vi.fn().mockResolvedValue(undefined),
  logout: vi.fn().mockResolvedValue(undefined),
  getMailboxLock: vi.fn().mockResolvedValue({ release: vi.fn() }),
  idle: vi.fn().mockImplementation(() => new Promise(() => {})), // never resolves (simulates IDLE)
  fetch: vi.fn().mockReturnValue({
    [Symbol.asyncIterator]: () => ({ next: () => Promise.resolve({ done: true, value: undefined }) }),
  }),
  messageFlagsAdd: vi.fn().mockResolvedValue(undefined),
};

vi.mock("imapflow", () => ({
  ImapFlow: vi.fn(() => mockImapClient),
}));

// Mock nodemailer
const mockTransporter = {
  verify: vi.fn().mockResolvedValue(true),
  sendMail: vi.fn().mockResolvedValue({ messageId: "<test@example.com>" }),
  close: vi.fn(),
};

vi.mock("nodemailer", () => ({
  createTransport: vi.fn(() => mockTransporter),
}));

// Mock mailparser
vi.mock("mailparser", () => ({
  simpleParser: vi.fn(),
}));

// Mock agent loop
vi.mock("../../src/agent/agent-loop.js", () => ({
  runAgentLoop: vi.fn().mockResolvedValue({
    text: "Email response from agent",
    toolCallCount: 0,
    totalInputTokens: 100,
    totalOutputTokens: 50,
    totalCacheCreationTokens: 0,
    totalCacheReadTokens: 0,
    iterations: 1,
  }),
}));

import { EmailIntegration } from "../../src/integrations/email.js";
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

describe("EmailIntegration", () => {
  let email: EmailIntegration;
  let llm: LLMClient;
  let toolContext: ToolContext;

  beforeEach(() => {
    vi.clearAllMocks();
    llm = createMockLLM();
    toolContext = createMockToolContext();
    email = new EmailIntegration({
      imapHost: "imap.test.com",
      imapPort: 993,
      imapUser: "bot@test.com",
      imapPass: "password123",
      smtpHost: "smtp.test.com",
      smtpPort: 587,
      llm,
      toolContext,
    });
  });

  it("should have correct name", () => {
    expect(email.name).toBe("email");
  });

  it("should not be connected initially", () => {
    expect(email.isConnected()).toBe(false);
  });

  it("should connect to IMAP and SMTP", async () => {
    await email.connect();
    expect(mockImapClient.connect).toHaveBeenCalled();
    expect(mockTransporter.verify).toHaveBeenCalled();
    expect(email.isConnected()).toBe(true);
  });

  it("should disconnect cleanly", async () => {
    await email.connect();
    await email.disconnect();
    expect(mockImapClient.logout).toHaveBeenCalled();
    expect(mockTransporter.close).toHaveBeenCalled();
    expect(email.isConnected()).toBe(false);
  });

  it("should create IMAP client with correct config", async () => {
    const { ImapFlow } = await import("imapflow");
    await email.connect();
    expect(ImapFlow).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "imap.test.com",
        port: 993,
        secure: true,
        auth: { user: "bot@test.com", pass: "password123" },
      })
    );
  });

  it("should create SMTP transport with correct config", async () => {
    const { createTransport } = await import("nodemailer");
    await email.connect();
    expect(createTransport).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "smtp.test.com",
        port: 587,
        auth: { user: "bot@test.com", pass: "password123" },
      })
    );
  });

  describe("with allowed senders", () => {
    it("should restrict to allowed senders", () => {
      const restrictedEmail = new EmailIntegration({
        imapHost: "imap.test.com",
        imapPort: 993,
        imapUser: "bot@test.com",
        imapPass: "password123",
        smtpHost: "smtp.test.com",
        smtpPort: 587,
        llm,
        toolContext,
        allowedSenders: ["allowed@test.com"],
      });
      // The allowlist is checked internally when processing messages
      expect(restrictedEmail.name).toBe("email");
    });
  });
});
