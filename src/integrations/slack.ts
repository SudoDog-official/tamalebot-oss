// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Slack Integration
 *
 * Connects a TamaleBot agent to Slack via Socket Mode (WebSocket).
 * The container initiates an outbound WebSocket — no public URL needed.
 *
 * Setup:
 * 1. Create a Slack app at https://api.slack.com/apps
 * 2. Enable Socket Mode and generate an app-level token (xapp-...)
 * 3. Add bot scopes: chat:write, app_mentions:read, im:history, channels:history
 * 4. Install to workspace and get the bot token (xoxb-...)
 * 5. Set SLACK_BOT_TOKEN and SLACK_APP_TOKEN in your environment
 *
 * The bot responds to @mentions in channels and direct messages.
 */

import { App } from "@slack/bolt";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "../agent/llm-client.js";
import { runAgentLoop } from "../agent/agent-loop.js";
import type { ToolContext } from "../agent/tools.js";
import type { ModelRouter } from "../agent/model-router.js";
import type { Integration } from "./index.js";

/** Minimal event shape covering both app_mention and message events */
interface SlackEvent {
  text?: string;
  user?: string;
  bot_id?: string;
  subtype?: string;
  channel: string;
  channel_type?: string;
  team?: string;
  ts: string;
  thread_ts?: string;
}

interface SlackConfig {
  botToken: string;
  appToken: string;
  llm: LLMClient;
  toolContext: ToolContext;
  router?: ModelRouter;
  allowedChannelIds?: string[];
}

export class SlackIntegration implements Integration {
  name = "slack";
  private app: App;
  private llm: LLMClient;
  private toolContext: ToolContext;
  private router?: ModelRouter;
  private allowedChannelIds: Set<string> | null;
  private connected = false;
  private botUserId: string | null = null;
  private conversations: Map<string, MessageParam[]> = new Map();

  constructor(config: SlackConfig) {
    this.llm = config.llm;
    this.toolContext = config.toolContext;
    this.router = config.router;
    this.allowedChannelIds = config.allowedChannelIds
      ? new Set(config.allowedChannelIds)
      : null;

    this.app = new App({
      token: config.botToken,
      appToken: config.appToken,
      socketMode: true,
    });
  }

  async connect(): Promise<void> {
    // Handle app mentions in channels
    this.app.event("app_mention", async ({ event, say }) => {
      await this.handleMessage(event as SlackEvent, say);
    });

    // Handle direct messages
    this.app.event("message", async ({ event, say }) => {
      const msg = event as SlackEvent;
      if (msg.channel_type === "im") {
        await this.handleMessage(msg, say);
      }
    });

    await this.app.start();

    // Fetch bot user ID for stripping mentions
    const auth = await this.app.client.auth.test();
    this.botUserId = auth.user_id as string;
    this.connected = true;
    console.log(`[slack] Connected as ${auth.user} (Socket Mode)`);
  }

  async disconnect(): Promise<void> {
    await this.app.stop();
    this.connected = false;
    console.log("[slack] Disconnected");
  }

  isConnected(): boolean {
    return this.connected;
  }

  private getConversationKey(event: SlackEvent): string {
    const isDM = event.channel_type === "im";
    if (isDM) {
      return `dm-${event.user}`;
    }
    const teamId = event.team ?? "unknown";
    return `${teamId}-${event.channel}`;
  }

  private async handleMessage(
    event: SlackEvent,
    say: (msg: { text: string; thread_ts?: string }) => Promise<unknown>
  ): Promise<void> {
    // Ignore bot messages
    if (event.bot_id || event.subtype === "bot_message") return;

    // Strip bot mention from text
    let text = (event.text ?? "").trim();
    if (this.botUserId) {
      text = text.replace(new RegExp(`<@${this.botUserId}>`, "g"), "").trim();
    }
    if (!text) return;

    // Channel allowlist check
    if (this.allowedChannelIds && !this.allowedChannelIds.has(event.channel)) {
      console.log(`[slack] Ignoring message from unauthorized channel ${event.channel}`);
      return;
    }

    const threadTs = event.thread_ts ?? event.ts;
    const key = this.getConversationKey(event);

    console.log(`[slack] ${event.user} (${key}): ${text.slice(0, 100)}`);

    // Handle commands
    if (text === "/clear") {
      this.conversations.delete(key);
      await say({ text: "Conversation cleared.", thread_ts: threadTs });
      return;
    }

    if (text === "/status") {
      const history = this.conversations.get(key) ?? [];
      await say({
        text:
          `Agent: ${this.toolContext.agentId}\n` +
          `Model: ${this.llm.getModel()}\n` +
          `Conversation: ${history.length} messages`,
        thread_ts: threadTs,
      });
      return;
    }

    // Get or create conversation history
    let history = this.conversations.get(key);
    if (!history) {
      history = [];
      this.conversations.set(key, history);
    }

    try {
      // Route through model router if available
      let selectedLLM = this.llm;
      if (this.router) {
        const route = await this.router.route(text, history);
        selectedLLM = route.llm;
        console.log(`  [slack:router] ${route.classification} → ${selectedLLM.getModel()}`);
      }

      const response = await runAgentLoop(text, history, {
        llm: selectedLLM,
        toolContext: this.toolContext,
        onToolCall(name, input) {
          console.log(`  [slack:tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
        },
      });

      // Send response (split into chunks if too long)
      const responseText = response.text || "(No response)";
      await this.sendLongMessage(say, responseText, threadTs);

      // Append stats if tools were used
      if (response.toolCallCount > 0) {
        const stats =
          `_${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens_`;
        await say({ text: stats, thread_ts: threadTs });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[slack] Error processing message: ${msg}`);
      await say({ text: `Error: ${msg.slice(0, 200)}`, thread_ts: threadTs });
    }
  }

  private async sendLongMessage(
    say: (msg: { text: string; thread_ts?: string }) => Promise<unknown>,
    text: string,
    threadTs?: string
  ): Promise<void> {
    const MAX_LENGTH = 4000;
    if (text.length <= MAX_LENGTH) {
      await say({ text, thread_ts: threadTs });
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
      await say({ text: chunk, thread_ts: threadTs });
    }
  }
}
