// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * WhatsApp Integration
 *
 * Connects a TamaleBot agent to WhatsApp via the Cloud API (Meta Business Platform).
 * Uses webhooks for receiving messages (not polling/WebSocket).
 *
 * Setup:
 * 1. Create an app at https://developers.facebook.com
 * 2. Add WhatsApp product to the app
 * 3. Get a permanent access token, phone number ID, and set a verify token
 * 4. Set WHATSAPP_TOKEN, WHATSAPP_PHONE_ID, WHATSAPP_VERIFY_TOKEN in your environment
 * 5. Register your webhook URL:
 *    https://tamalebot-worker.om-d67.workers.dev/api/agent/{name}/webhook/whatsapp
 *
 * Free tier: 1,000 service conversations/month, unlimited inbound messages.
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "../agent/llm-client.js";
import { runAgentLoop } from "../agent/agent-loop.js";
import type { ToolContext } from "../agent/tools.js";
import type { Integration } from "./index.js";

const GRAPH_API = "https://graph.facebook.com/v21.0";

interface WhatsAppConfig {
  accessToken: string;
  phoneNumberId: string;
  verifyToken: string;
  llm: LLMClient;
  toolContext: ToolContext;
}

export class WhatsAppIntegration implements Integration {
  name = "whatsapp";
  private accessToken: string;
  private phoneNumberId: string;
  private verifyToken: string;
  private llm: LLMClient;
  private toolContext: ToolContext;
  private conversations: Map<string, MessageParam[]> = new Map();
  private connected = false;

  constructor(config: WhatsAppConfig) {
    this.accessToken = config.accessToken;
    this.phoneNumberId = config.phoneNumberId;
    this.verifyToken = config.verifyToken;
    this.llm = config.llm;
    this.toolContext = config.toolContext;
  }

  async connect(): Promise<void> {
    // Validate token by checking the phone number endpoint
    try {
      const res = await fetch(`${GRAPH_API}/${this.phoneNumberId}`, {
        headers: { Authorization: `Bearer ${this.accessToken}` },
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`WhatsApp API validation failed (${res.status}): ${body.slice(0, 200)}`);
      }
      console.log(`[whatsapp] Connected (phone: ${this.phoneNumberId})`);
      this.connected = true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[whatsapp] Connection failed: ${msg}`);
      // Mark as connected anyway so webhook routes are active
      // The actual API calls will fail with clear error messages
      this.connected = true;
    }
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    console.log("[whatsapp] Disconnected");
  }

  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Handle webhook verification (GET request from Meta).
   * Meta sends hub.mode, hub.verify_token, and hub.challenge.
   */
  handleVerify(params: URLSearchParams): { status: number; body: string } {
    const mode = params.get("hub.mode");
    const token = params.get("hub.verify_token");
    const challenge = params.get("hub.challenge");

    if (mode === "subscribe" && token === this.verifyToken) {
      console.log("[whatsapp] Webhook verified");
      return { status: 200, body: challenge || "" };
    }
    return { status: 403, body: "Forbidden" };
  }

  /**
   * Handle incoming webhook payload (POST from Meta).
   * Must be called asynchronously — the HTTP handler should respond 200 immediately.
   */
  async handleWebhook(payload: Record<string, unknown>): Promise<void> {
    try {
      const entries = (payload.entry as Array<Record<string, unknown>>) ?? [];
      for (const entry of entries) {
        const changes = (entry.changes as Array<Record<string, unknown>>) ?? [];
        for (const change of changes) {
          const value = change.value as Record<string, unknown>;
          if (!value) continue;

          // Skip status updates (delivery, read receipts)
          if (value.statuses) continue;

          const messages = (value.messages as Array<Record<string, unknown>>) ?? [];
          for (const msg of messages) {
            await this.handleIncomingMessage(msg);
          }
        }
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[whatsapp] Webhook processing error: ${errMsg}`);
    }
  }

  private async handleIncomingMessage(msg: Record<string, unknown>): Promise<void> {
    const type = msg.type as string;
    const from = msg.from as string; // Phone number

    // Only handle text messages for now
    if (type !== "text") {
      console.log(`[whatsapp] Ignoring non-text message type: ${type}`);
      return;
    }

    const textObj = msg.text as Record<string, unknown>;
    const text = (textObj?.body as string) ?? "";
    if (!text) return;

    console.log(`[whatsapp] ${from}: ${text.slice(0, 100)}`);

    // Handle commands
    if (text === "/clear") {
      this.conversations.delete(from);
      await this.sendMessage(from, "Conversation cleared.");
      return;
    }

    if (text === "/status") {
      const history = this.conversations.get(from) ?? [];
      await this.sendMessage(
        from,
        `Agent: ${this.toolContext.agentId}\n` +
        `Model: ${this.llm.getModel()}\n` +
        `Conversation: ${history.length} messages`
      );
      return;
    }

    // Get or create conversation history
    let history = this.conversations.get(from);
    if (!history) {
      history = [];
      this.conversations.set(from, history);
    }

    try {
      const response = await runAgentLoop(text, history, {
        llm: this.llm,
        toolContext: this.toolContext,
        onToolCall(name, input) {
          console.log(`  [whatsapp:tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
        },
      });

      const responseText = response.text || "(No response)";
      await this.sendLongMessage(from, responseText);

      if (response.toolCallCount > 0) {
        await this.sendMessage(
          from,
          `_${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens_`
        );
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[whatsapp] Error processing message: ${errMsg}`);
      await this.sendMessage(from, `Error: ${errMsg.slice(0, 200)}`);
    }
  }

  private async sendMessage(to: string, text: string): Promise<void> {
    const res = await fetch(`${GRAPH_API}/${this.phoneNumberId}/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.accessToken}`,
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "text",
        text: { body: text },
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      console.error(`[whatsapp] Send failed (${res.status}): ${body.slice(0, 200)}`);
    }
  }

  private async sendLongMessage(to: string, text: string): Promise<void> {
    const MAX_LENGTH = 4000; // Leave room below WhatsApp's 4096 limit
    if (text.length <= MAX_LENGTH) {
      await this.sendMessage(to, text);
      return;
    }

    let remaining = text;
    while (remaining.length > 0) {
      let chunk: string;
      if (remaining.length <= MAX_LENGTH) {
        chunk = remaining;
        remaining = "";
      } else {
        const splitAt = remaining.lastIndexOf("\n", MAX_LENGTH);
        if (splitAt > MAX_LENGTH / 2) {
          chunk = remaining.slice(0, splitAt);
          remaining = remaining.slice(splitAt + 1);
        } else {
          chunk = remaining.slice(0, MAX_LENGTH);
          remaining = remaining.slice(MAX_LENGTH);
        }
      }
      await this.sendMessage(to, chunk);
    }
  }
}
