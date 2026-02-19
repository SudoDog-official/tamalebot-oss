// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Telegram Integration
 *
 * Connects a TamaleBot agent to Telegram via the Bot API.
 * Uses long polling (not webhooks) for simplicity in Phase 1.
 *
 * Setup:
 * 1. Create a bot via @BotFather on Telegram
 * 2. Set TELEGRAM_BOT_TOKEN in your environment
 * 3. Start the agent with Telegram integration enabled
 *
 * The bot accepts messages and runs them through the agent loop,
 * sending responses back to the Telegram chat.
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "../agent/llm-client.js";
import { runAgentLoop } from "../agent/agent-loop.js";
import type { ToolContext } from "../agent/tools.js";
import type { Integration } from "./index.js";

const TELEGRAM_API = "https://api.telegram.org/bot";

interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    chat: { id: number; type: string; title?: string; first_name?: string };
    from?: { id: number; first_name: string; username?: string };
    text?: string;
    date: number;
  };
}

interface TelegramConfig {
  botToken: string;
  llm: LLMClient;
  toolContext: ToolContext;
  allowedChatIds?: number[];
}

export class TelegramIntegration implements Integration {
  name = "telegram";
  private token: string;
  private llm: LLMClient;
  private toolContext: ToolContext;
  private allowedChatIds: Set<number> | null;
  private running = false;
  private offset = 0;
  private conversations: Map<number, MessageParam[]> = new Map();

  constructor(config: TelegramConfig) {
    this.token = config.botToken;
    this.llm = config.llm;
    this.toolContext = config.toolContext;
    this.allowedChatIds = config.allowedChatIds
      ? new Set(config.allowedChatIds)
      : null;
  }

  async connect(): Promise<void> {
    // Verify the bot token works
    const me = await this.apiCall("getMe");
    if (!me.ok) {
      throw new Error(`Telegram bot token invalid: ${JSON.stringify(me)}`);
    }

    console.log(`[telegram] Connected as @${me.result.username}`);
    this.running = true;
    this.pollLoop();
  }

  async disconnect(): Promise<void> {
    this.running = false;
    console.log("[telegram] Disconnected");
  }

  isConnected(): boolean {
    return this.running;
  }

  private async apiCall(method: string, body?: Record<string, unknown>): Promise<any> {
    const url = `${TELEGRAM_API}${this.token}/${method}`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    return response.json();
  }

  private async pollLoop(): Promise<void> {
    while (this.running) {
      try {
        const updates = await this.apiCall("getUpdates", {
          offset: this.offset,
          timeout: 30,
          allowed_updates: ["message"],
        });

        if (updates.ok && updates.result.length > 0) {
          for (const update of updates.result as TelegramUpdate[]) {
            this.offset = update.update_id + 1;
            await this.handleUpdate(update);
          }
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[telegram] Poll error: ${msg}`);
        // Wait before retrying on error
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }

  private async handleUpdate(update: TelegramUpdate): Promise<void> {
    const message = update.message;
    if (!message?.text) return;

    const chatId = message.chat.id;
    const text = message.text;
    const from = message.from?.first_name ?? "User";

    // Chat ID allowlist check
    if (this.allowedChatIds && !this.allowedChatIds.has(chatId)) {
      console.log(`[telegram] Ignoring message from unauthorized chat ${chatId}`);
      return;
    }

    console.log(`[telegram] ${from} (chat ${chatId}): ${text.slice(0, 100)}`);

    // Handle bot commands
    if (text === "/start") {
      await this.sendMessage(chatId, "Hi! I'm a TamaleBot agent. Send me a message and I'll help you out.");
      return;
    }

    if (text === "/clear") {
      this.conversations.delete(chatId);
      await this.sendMessage(chatId, "Conversation cleared.");
      return;
    }

    if (text === "/status") {
      const history = this.conversations.get(chatId) ?? [];
      await this.sendMessage(
        chatId,
        `Agent: ${this.toolContext.agentId}\n` +
        `Model: ${this.llm.getModel()}\n` +
        `Conversation: ${history.length} messages`
      );
      return;
    }

    // Send "typing" indicator
    await this.apiCall("sendChatAction", { chat_id: chatId, action: "typing" });

    // Get or create conversation history for this chat
    let history = this.conversations.get(chatId);
    if (!history) {
      history = [];
      this.conversations.set(chatId, history);
    }

    try {
      const response = await runAgentLoop(text, history, {
        llm: this.llm,
        toolContext: this.toolContext,
        onToolCall(name, input) {
          console.log(`  [telegram:tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
        },
      });

      // Send response (split into chunks if too long for Telegram's 4096 char limit)
      const responseText = response.text || "(No response)";
      await this.sendLongMessage(chatId, responseText);

      // Append stats if tools were used
      if (response.toolCallCount > 0) {
        const stats =
          `_${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens_`;
        await this.sendMessage(chatId, stats, "MarkdownV2");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[telegram] Error processing message: ${msg}`);
      await this.sendMessage(chatId, `Error: ${msg.slice(0, 200)}`);
    }
  }

  private async sendMessage(
    chatId: number,
    text: string,
    parseMode?: string
  ): Promise<void> {
    await this.apiCall("sendMessage", {
      chat_id: chatId,
      text,
      parse_mode: parseMode,
    });
  }

  private async sendLongMessage(chatId: number, text: string): Promise<void> {
    const MAX_LENGTH = 4000; // Leave some room below Telegram's 4096 limit
    if (text.length <= MAX_LENGTH) {
      await this.sendMessage(chatId, text);
      return;
    }

    // Split on newlines, falling back to hard splits
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
      await this.sendMessage(chatId, chunk);
    }
  }
}
