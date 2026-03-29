// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Discord Integration
 *
 * Connects a TamaleBot agent to Discord via the Gateway (WebSocket).
 * Uses discord.js for real-time message handling.
 *
 * Setup:
 * 1. Create an app at https://discord.com/developers/applications
 * 2. Add a Bot, copy the bot token
 * 3. Invite the bot to your server with the OAuth2 URL Generator
 *    (scopes: bot; permissions: Send Messages, Read Message History)
 * 4. Set DISCORD_BOT_TOKEN in your environment
 *
 * The bot responds to messages in channels it has access to and DMs.
 * Completely free — no API costs.
 */

import {
  Client,
  GatewayIntentBits,
  Partials,
  type Message,
} from "discord.js";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "../agent/llm-client.js";
import { runAgentLoop } from "../agent/agent-loop.js";
import type { ToolContext } from "../agent/tools.js";
import type { ModelRouter } from "../agent/model-router.js";
import type { Integration } from "./index.js";
import { BoundedConversationMap } from "./conversation-map.js";

interface DiscordConfig {
  botToken: string;
  llm: LLMClient;
  toolContext: ToolContext;
  router?: ModelRouter;
  allowedGuildIds?: string[];
}

export class DiscordIntegration implements Integration {
  name = "discord";
  private client: Client;
  private token: string;
  private llm: LLMClient;
  private toolContext: ToolContext;
  private router?: ModelRouter;
  private allowedGuildIds: Set<string> | null;
  private conversations = new BoundedConversationMap<string>();
  private connected = false;

  constructor(config: DiscordConfig) {
    this.token = config.botToken;
    this.llm = config.llm;
    this.toolContext = config.toolContext;
    this.router = config.router;
    this.allowedGuildIds = config.allowedGuildIds
      ? new Set(config.allowedGuildIds)
      : null;

    this.client = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
      ],
      partials: [Partials.Channel], // Required for DMs
    });
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.client.once("ready", () => {
        console.log(`[discord] Connected as ${this.client.user?.tag}`);
        this.connected = true;
        resolve();
      });

      this.client.on("messageCreate", (msg) => {
        this.handleMessage(msg).catch((err) => {
          console.error(`[discord] Message handler error: ${err.message}`);
        });
      });

      this.client.login(this.token).catch(reject);
    });
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    this.client.destroy();
    console.log("[discord] Disconnected");
  }

  isConnected(): boolean {
    return this.connected;
  }

  private getConversationKey(msg: Message): string {
    if (msg.guild) {
      return `${msg.guild.id}-${msg.channel.id}`;
    }
    return `dm-${msg.author.id}`;
  }

  private async handleMessage(msg: Message): Promise<void> {
    // Ignore bot messages (including own)
    if (msg.author.bot) return;

    // Only respond if mentioned or in DMs
    const isDM = !msg.guild;
    const isMentioned = msg.mentions.has(this.client.user!);
    if (!isDM && !isMentioned) return;

    const text = msg.content
      .replace(new RegExp(`<@!?${this.client.user!.id}>`, "g"), "")
      .trim();
    if (!text) return;

    // Guild allowlist check
    if (msg.guild && this.allowedGuildIds && !this.allowedGuildIds.has(msg.guild.id)) {
      console.log(`[discord] Ignoring message from unauthorized guild ${msg.guild.id}`);
      return;
    }

    console.log(`[discord] ${msg.author.tag}: ${text.slice(0, 100)}`);

    // Handle commands
    if (text === "/clear") {
      this.conversations.delete(this.getConversationKey(msg));
      await msg.reply("Conversation cleared.");
      return;
    }

    if (text === "/status") {
      const key = this.getConversationKey(msg);
      const history = this.conversations.get(key) ?? [];
      await msg.reply(
        `Agent: ${this.toolContext.agentId}\n` +
        `Model: ${this.llm.getModel()}\n` +
        `Conversation: ${history.length} messages`
      );
      return;
    }

    // Show typing indicator (not available on all channel types)
    if ("sendTyping" in msg.channel) {
      await msg.channel.sendTyping();
    }

    // Get or create conversation history
    const key = this.getConversationKey(msg);
    const history = this.conversations.getOrCreate(key);

    try {
      // Route through model router if available
      let selectedLLM = this.llm;
      if (this.router) {
        const route = await this.router.route(text, history);
        selectedLLM = route.llm;
        console.log(`  [discord:router] ${route.classification} → ${selectedLLM.getModel()}`);
      }

      const loopConfig = {
        llm: selectedLLM,
        toolContext: this.toolContext,
        onToolCall(name: string, input: Record<string, unknown>) {
          console.log(`  [discord:tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
        },
      };

      const response = await runAgentLoop(text, history, loopConfig);

      // Send response (chunked for Discord's 2000 char limit)
      const responseText = response.text || "(No response)";
      await this.sendLongMessage(msg, responseText);

      // Append stats if tools were used
      if (response.toolCallCount > 0 && "send" in msg.channel) {
        await msg.channel.send(
          `*${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens*`
        );
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[discord] Error processing message: ${errMsg}`);
      await msg.reply(`Error: ${errMsg.slice(0, 200)}`);
    }
  }

  private async sendLongMessage(msg: Message, text: string): Promise<void> {
    const MAX_LENGTH = 1900; // Leave room below Discord's 2000 limit
    if (text.length <= MAX_LENGTH) {
      await msg.reply(text);
      return;
    }

    // Split on newlines, falling back to hard splits
    let remaining = text;
    let first = true;
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
      if (first) {
        await msg.reply(chunk);
        first = false;
      } else if ("send" in msg.channel) {
        await msg.channel.send(chunk);
      }
    }
  }
}
