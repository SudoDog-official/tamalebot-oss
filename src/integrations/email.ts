// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Email Integration (IMAP + SMTP)
 *
 * Connects a TamaleBot agent to any email provider via IMAP/SMTP.
 * Uses IMAP IDLE for efficient push notifications of new emails.
 *
 * Setup:
 * 1. Configure IMAP access (for Gmail: enable "Less secure apps" or use App Password)
 * 2. Set EMAIL_IMAP_HOST, EMAIL_IMAP_USER, EMAIL_IMAP_PASS
 * 3. Optionally set EMAIL_SMTP_HOST (defaults to imap host with "imap." → "smtp.")
 * 4. Set EMAIL_ALLOWED_SENDERS to restrict who can email the agent
 *
 * The agent reads incoming emails, processes them, and replies in-thread.
 */

import { ImapFlow } from "imapflow";
import { createTransport, type Transporter } from "nodemailer";
import { simpleParser, type ParsedMail } from "mailparser";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "../agent/llm-client.js";
import { runAgentLoop } from "../agent/agent-loop.js";
import type { ToolContext } from "../agent/tools.js";
import type { ModelRouter } from "../agent/model-router.js";
import type { Integration } from "./index.js";
import { BoundedConversationMap } from "./conversation-map.js";

interface EmailConfig {
  imapHost: string;
  imapPort: number;
  imapUser: string;
  imapPass: string;
  smtpHost: string;
  smtpPort: number;
  smtpUser?: string;
  smtpPass?: string;
  llm: LLMClient;
  toolContext: ToolContext;
  router?: ModelRouter;
  allowedSenders?: string[];
}

export class EmailIntegration implements Integration {
  name = "email";
  private config: EmailConfig;
  private imapClient!: ImapFlow;
  private smtp!: Transporter;
  private llm: LLMClient;
  private toolContext: ToolContext;
  private router?: ModelRouter;
  private allowedSenders: Set<string> | null;
  private conversations = new BoundedConversationMap<string>();
  private connected = false;
  private running = false;

  constructor(config: EmailConfig) {
    this.config = config;
    this.llm = config.llm;
    this.toolContext = config.toolContext;
    this.router = config.router;
    this.allowedSenders = config.allowedSenders
      ? new Set(config.allowedSenders.map((s) => s.toLowerCase()))
      : null;
  }

  async connect(): Promise<void> {
    // Create IMAP client
    this.imapClient = new ImapFlow({
      host: this.config.imapHost,
      port: this.config.imapPort,
      secure: true,
      auth: {
        user: this.config.imapUser,
        pass: this.config.imapPass,
      },
      logger: false,
    });

    // Create SMTP transport
    this.smtp = createTransport({
      host: this.config.smtpHost,
      port: this.config.smtpPort,
      secure: this.config.smtpPort === 465,
      auth: {
        user: this.config.smtpUser ?? this.config.imapUser,
        pass: this.config.smtpPass ?? this.config.imapPass,
      },
    });

    // Connect IMAP
    await this.imapClient.connect();
    console.log(`[email] IMAP connected to ${this.config.imapHost}`);

    // Verify SMTP
    await this.smtp.verify();
    console.log(`[email] SMTP connected to ${this.config.smtpHost}`);

    this.connected = true;
    this.running = true;
    this.idleLoop(); // fire-and-forget
  }

  async disconnect(): Promise<void> {
    this.running = false;
    try {
      await this.imapClient.logout();
    } catch {
      // Best effort
    }
    this.smtp.close();
    this.connected = false;
    console.log("[email] Disconnected");
  }

  isConnected(): boolean {
    return this.connected;
  }

  private async idleLoop(): Promise<void> {
    while (this.running) {
      try {
        const lock = await this.imapClient.getMailboxLock("INBOX");
        try {
          // Process any existing unseen messages
          await this.processNewMessages();

          // IDLE — waits for server to notify of new messages
          await this.imapClient.idle();
        } finally {
          lock.release();
        }

        // After IDLE breaks (new message arrived), process
        if (this.running) {
          const lock2 = await this.imapClient.getMailboxLock("INBOX");
          try {
            await this.processNewMessages();
          } finally {
            lock2.release();
          }
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[email] IDLE loop error: ${msg}`);
        if (this.running) {
          await new Promise((r) => setTimeout(r, 10000)); // retry after 10s
        }
      }
    }
  }

  private async processNewMessages(): Promise<void> {
    const messages = this.imapClient.fetch({ seen: false }, {
      source: true,
      uid: true,
      flags: true,
    });

    for await (const msg of messages) {
      try {
        if (!msg.source) continue;
        const parsed = await simpleParser(msg.source) as ParsedMail;
        await this.handleEmail(parsed);
        // Mark as SEEN
        await this.imapClient.messageFlagsAdd({ uid: msg.uid }, ["\\Seen"], { uid: true });
      } catch (err) {
        console.error(`[email] Error processing message: ${err instanceof Error ? err.message : err}`);
      }
    }
  }

  private async handleEmail(parsed: ParsedMail): Promise<void> {
    const from = parsed.from?.value?.[0]?.address;
    if (!from) return;

    // Sender allowlist
    if (this.allowedSenders && !this.allowedSenders.has(from.toLowerCase())) {
      console.log(`[email] Ignoring email from unauthorized sender: ${from}`);
      return;
    }

    const subject = parsed.subject ?? "(no subject)";
    const body = (parsed.text ?? "").trim();
    if (!body) return;

    console.log(`[email] From: ${from}, Subject: ${subject}`);

    // Handle commands via subject line
    if (subject.toLowerCase().includes("clear")) {
      this.conversations.delete(from);
      await this.sendReply(from, `Re: ${subject}`, "Conversation cleared.", parsed.messageId);
      return;
    }

    if (subject.toLowerCase().includes("status")) {
      const history = this.conversations.get(from) ?? [];
      await this.sendReply(
        from,
        `Re: ${subject}`,
        `Agent: ${this.toolContext.agentId}\nModel: ${this.llm.getModel()}\nConversation: ${history.length} messages`,
        parsed.messageId
      );
      return;
    }

    // Conversation key: sender email
    const history = this.conversations.getOrCreate(from);

    try {
      // Route through model router if available
      let selectedLLM = this.llm;
      if (this.router) {
        const route = await this.router.route(body, history);
        selectedLLM = route.llm;
        console.log(`  [email:router] ${route.classification} → ${selectedLLM.getModel()}`);
      }

      const loopConfig = {
        llm: selectedLLM,
        toolContext: this.toolContext,
        onToolCall(name: string, input: Record<string, unknown>) {
          console.log(`  [email:tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
        },
      };

      const response = await runAgentLoop(body, history, loopConfig);

      let responseText = response.text || "(No response)";
      if (response.toolCallCount > 0) {
        responseText +=
          `\n\n---\n${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens`;
      }

      // Build threading headers
      const replySubject = subject.startsWith("Re:") ? subject : `Re: ${subject}`;
      const refs = parsed.references
        ? (Array.isArray(parsed.references) ? parsed.references.join(" ") : parsed.references) +
          " " +
          (parsed.messageId ?? "")
        : parsed.messageId ?? "";

      await this.sendReply(from, replySubject, responseText, parsed.messageId, refs.trim());
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[email] Error: ${errMsg}`);
      await this.sendReply(from, `Re: ${subject}`, `Error: ${errMsg.slice(0, 500)}`, parsed.messageId);
    }
  }

  private async sendReply(
    to: string,
    subject: string,
    body: string,
    inReplyTo?: string,
    references?: string
  ): Promise<void> {
    await this.smtp.sendMail({
      from: this.config.imapUser,
      to,
      subject,
      text: body,
      ...(inReplyTo ? { inReplyTo } : {}),
      ...(references ? { references } : {}),
    });
  }
}
