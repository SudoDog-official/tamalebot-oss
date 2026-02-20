// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Agent Runtime
 *
 * This is the process that runs inside each agent's Docker container
 * (or locally via `tamalebot run`). It:
 * 1. Connects to the Claude API
 * 2. Accepts messages (via HTTP in container mode, or stdin in standalone mode)
 * 3. Runs the tool-use loop with security policy enforcement
 * 4. Returns responses
 *
 * Modes:
 *   TAMALEBOT_MODE=http   → HTTP server (for Cloudflare Containers)
 *   TAMALEBOT_MODE=repl   → Interactive stdin REPL (default)
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createInterface } from "node:readline";
import { homedir } from "node:os";
import { join } from "node:path";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import { PolicyEngine } from "../security/policy-engine.js";
import { AuditTrail } from "../security/audit-trail.js";
import { SecretManager } from "../security/secret-manager.js";
import { LLMClient } from "./llm-client.js";
import { runAgentLoop } from "./agent-loop.js";
import type { ToolContext } from "./tools.js";
import type { StorageBackend } from "../storage/index.js";

const agentId = process.env.TAMALEBOT_AGENT_ID ?? "standalone";
const policyName = process.env.TAMALEBOT_POLICY ?? "default";
const model = process.env.TAMALEBOT_MODEL ?? undefined;
const provider = process.env.TAMALEBOT_PROVIDER ?? undefined;
const agentName = process.env.TAMALEBOT_AGENT_NAME ?? "TamaleBot Agent";
const mode = process.env.TAMALEBOT_MODE ?? "repl";
const systemPromptOverride = process.env.TAMALEBOT_SYSTEM_PROMPT ?? "";

// Resolve API key: check provider-specific vars, then generic
const apiKey =
  process.env.ANTHROPIC_API_KEY ||
  process.env.OPENAI_API_KEY ||
  process.env.MOONSHOT_API_KEY ||
  process.env.GOOGLE_API_KEY ||
  process.env.MINIMAX_API_KEY ||
  process.env.TAMALEBOT_API_KEY ||
  "";

// Determine log and work directories based on environment
const isDocker = process.env.TAMALEBOT_DOCKER === "true" || mode === "http";
const logDir = isDocker ? "/tmp/logs" : join(homedir(), ".tamalebot", "logs");
const workDir = isDocker ? "/tmp/workspace" : process.cwd();

const policy = new PolicyEngine();
const audit = new AuditTrail(logDir, agentId);
const secrets = new SecretManager(audit);

function buildSystemPrompt(): string {
  if (systemPromptOverride) return systemPromptOverride;
  return `You are ${agentName}, a helpful AI agent powered by TamaleBot. You can execute shell commands, read and write files, and browse the web.

Guidelines:
- Use the tools available to you to accomplish tasks
- Always explain what you're doing before taking actions
- If a tool call is blocked by security policy, explain what happened and suggest alternatives
- Be concise and direct in your responses
- If you're unsure about something, say so rather than guessing`;
}

// --- Conversation Manager (in-memory + optional R2 persistence) ---

class ConversationManager {
  private cache = new Map<string, MessageParam[]>();
  private dirty = new Set<string>();
  private storage: StorageBackend | null;

  constructor(storage: StorageBackend | null) {
    this.storage = storage;
  }

  async get(chatId: string): Promise<MessageParam[]> {
    if (this.cache.has(chatId)) {
      return this.cache.get(chatId)!;
    }

    // Lazy-load from R2
    if (this.storage) {
      try {
        const data = await this.storage.get(`conversations/${chatId}.json`);
        if (data) {
          const history = JSON.parse(data.toString("utf-8")) as MessageParam[];
          this.cache.set(chatId, history);
          return history;
        }
      } catch (err) {
        console.error(`[memory] Failed to load ${chatId}: ${err instanceof Error ? err.message : err}`);
      }
    }

    const history: MessageParam[] = [];
    this.cache.set(chatId, history);
    return history;
  }

  markDirty(chatId: string): void {
    this.dirty.add(chatId);
  }

  async flush(): Promise<void> {
    if (!this.storage || this.dirty.size === 0) return;

    const promises: Promise<void>[] = [];
    for (const chatId of this.dirty) {
      const history = this.cache.get(chatId);
      if (history) {
        promises.push(
          this.storage.put(
            `conversations/${chatId}.json`,
            JSON.stringify(history)
          ).catch((err) => {
            console.error(`[memory] Failed to save ${chatId}: ${err instanceof Error ? err.message : err}`);
          }) as Promise<void>
        );
      }
    }
    await Promise.all(promises);
    this.dirty.clear();
  }

  delete(chatId: string): void {
    this.cache.delete(chatId);
    this.dirty.delete(chatId);
    if (this.storage) {
      this.storage.delete(`conversations/${chatId}.json`).catch(() => {});
    }
  }

  clear(): void {
    // Clear in-memory
    const keys = [...this.cache.keys()];
    this.cache.clear();
    this.dirty.clear();
    // Clear R2
    if (this.storage) {
      for (const key of keys) {
        this.storage.delete(`conversations/${key}.json`).catch(() => {});
      }
    }
  }

  get size(): number {
    return this.cache.size;
  }

  totalMessages(): number {
    let total = 0;
    for (const history of this.cache.values()) {
      total += history.length;
    }
    return total;
  }
}

// --- HTTP Server Mode ---

function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(body);
}

async function startHttpServer(llm: LLMClient, toolContext: ToolContext): Promise<void> {
  const port = Number(process.env.PORT) || 8080;
  const startTime = Date.now();

  // Initialize storage backend (R2 if worker URL available, otherwise in-memory only)
  const workerUrl = process.env.TAMALEBOT_WORKER_URL;
  const sanitizedName = (process.env.TAMALEBOT_AGENT_NAME ?? "agent")
    .toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 64);
  let storage: StorageBackend | null = null;
  if (workerUrl) {
    const { R2Storage } = await import("../storage/r2.js");
    storage = new R2Storage(workerUrl, sanitizedName);
    console.log("[tamalebot-agent] R2 persistent memory enabled");
  }

  // Per-chat conversation histories (in-memory + R2 persistence)
  const conversations = new ConversationManager(storage);

  // WhatsApp integration reference (needed by webhook routes)
  let whatsappIntegration: import("../integrations/whatsapp.js").WhatsAppIntegration | null = null;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${port}`);
    const path = url.pathname;

    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    // Health check
    if (path === "/health" && req.method === "GET") {
      sendJson(res, 200, {
        status: "ok",
        agentId,
        agentName,
        model: llm.getModel(),
        uptime: Math.floor((Date.now() - startTime) / 1000),
      });
      return;
    }

    // Message endpoint
    if (path === "/message" && req.method === "POST") {
      try {
        const body = await parseBody(req);
        const { text, chatId } = JSON.parse(body) as { text?: string; chatId?: string };

        if (!text || typeof text !== "string") {
          sendJson(res, 400, { error: "Missing 'text' field" });
          return;
        }

        const conversationKey = chatId ?? "default";
        const history = await conversations.get(conversationKey);

        const response = await runAgentLoop(text, history, {
          llm,
          toolContext,
          onToolCall(name, input) {
            console.log(`  [tool] ${name}: ${JSON.stringify(input).slice(0, 80)}`);
          },
          onToolResult(name, output, isError) {
            if (isError) {
              console.log(`  [tool] ${name}: ERROR - ${output.slice(0, 200)}`);
            }
          },
        });

        // Persist conversation to R2
        conversations.markDirty(conversationKey);
        await conversations.flush();

        sendJson(res, 200, {
          text: response.text,
          stats: {
            toolCalls: response.toolCallCount,
            iterations: response.iterations,
            inputTokens: response.totalInputTokens,
            outputTokens: response.totalOutputTokens,
            tokens: response.totalInputTokens + response.totalOutputTokens,
          },
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[http] Error processing message: ${msg}`);
        audit.log(agentId, "agent_error", msg, "blocked");
        sendJson(res, 500, { error: msg });
      }
      return;
    }

    // Audit log endpoint
    if (path === "/logs" && req.method === "GET") {
      try {
        const limitParam = url.searchParams.get("limit");
        const decisionParam = url.searchParams.get("decision");
        const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 200) : 50;

        const entries = await audit.getEntries({
          limit,
          agentId,
          decision: decisionParam === "allowed" || decisionParam === "blocked" ? decisionParam : undefined,
        });

        sendJson(res, 200, { entries, total: entries.length });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        sendJson(res, 500, { error: msg });
      }
      return;
    }

    // Clear conversation
    if (path === "/clear" && req.method === "POST") {
      try {
        const body = await parseBody(req);
        const { chatId } = JSON.parse(body || "{}") as { chatId?: string };
        const key = chatId ?? "default";
        conversations.delete(key);
        sendJson(res, 200, { cleared: true, chatId: key });
      } catch {
        conversations.clear();
        sendJson(res, 200, { cleared: true, chatId: "all" });
      }
      return;
    }

    // Memory stats
    if (path === "/memory/stats" && req.method === "GET") {
      sendJson(res, 200, {
        conversationCount: conversations.size,
        totalMessages: conversations.totalMessages(),
      });
      return;
    }

    // Clear all memory
    if (path === "/memory/clear" && req.method === "POST") {
      conversations.clear();
      sendJson(res, 200, { cleared: true });
      return;
    }

    // WhatsApp webhook verification (GET)
    if (path === "/webhook/whatsapp" && req.method === "GET") {
      if (whatsappIntegration) {
        const result = whatsappIntegration.handleVerify(url.searchParams);
        res.writeHead(result.status, {
          "Content-Type": "text/plain",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(result.body);
      } else {
        sendJson(res, 404, { error: "WhatsApp integration not configured" });
      }
      return;
    }

    // WhatsApp webhook incoming messages (POST)
    if (path === "/webhook/whatsapp" && req.method === "POST") {
      // Read body first, then ACK immediately (Meta requires <5s)
      const body = await parseBody(req);
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("OK");

      if (whatsappIntegration) {
        try {
          const payload = JSON.parse(body) as Record<string, unknown>;
          // Process async — don't await
          whatsappIntegration.handleWebhook(payload).catch((err) => {
            console.error(`[whatsapp] Async webhook error: ${err instanceof Error ? err.message : err}`);
          });
        } catch (err) {
          console.error(`[whatsapp] Webhook parse error: ${err instanceof Error ? err.message : err}`);
        }
      }
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  });

  server.listen(port, () => {
    console.log(`[tamalebot-agent] HTTP server listening on :${port}`);
  });

  // --- Start Integrations ---

  // Telegram (long-polling)
  const telegramToken = process.env.TELEGRAM_BOT_TOKEN;
  if (telegramToken) {
    const { TelegramIntegration } = await import("../integrations/telegram.js");
    const telegram = new TelegramIntegration({
      botToken: telegramToken,
      llm,
      toolContext,
    });
    await telegram.connect();
    console.log("[tamalebot-agent] Telegram integration started");
  }

  // Discord (WebSocket Gateway)
  const discordToken = process.env.DISCORD_BOT_TOKEN;
  if (discordToken) {
    const { DiscordIntegration } = await import("../integrations/discord.js");
    const discord = new DiscordIntegration({
      botToken: discordToken,
      llm,
      toolContext,
    });
    await discord.connect();
    console.log("[tamalebot-agent] Discord integration started");
  }

  // WhatsApp (webhook-based — routes handled above)
  const whatsappToken = process.env.WHATSAPP_TOKEN;
  const whatsappPhoneId = process.env.WHATSAPP_PHONE_ID;
  const whatsappVerifyToken = process.env.WHATSAPP_VERIFY_TOKEN;
  if (whatsappToken && whatsappPhoneId && whatsappVerifyToken) {
    const { WhatsAppIntegration } = await import("../integrations/whatsapp.js");
    whatsappIntegration = new WhatsAppIntegration({
      accessToken: whatsappToken,
      phoneNumberId: whatsappPhoneId,
      verifyToken: whatsappVerifyToken,
      llm,
      toolContext,
    });
    await whatsappIntegration.connect();
    console.log("[tamalebot-agent] WhatsApp integration started");
  }

  // Graceful shutdown
  const shutdown = () => {
    console.log(`[tamalebot-agent] HTTP server shutting down`);
    server.close();
    audit.log(agentId, "agent_stop", agentName, "allowed");
    audit.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// --- REPL Mode ---

async function startRepl(llm: LLMClient, toolContext: ToolContext): Promise<void> {
  console.log(`[tamalebot-agent] Type a message to chat. Ctrl+C to exit.\n`);

  const conversationHistory: MessageParam[] = [];

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "you> ",
  });

  rl.prompt();

  rl.on("line", async (line) => {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      return;
    }

    // Special commands
    if (input === "/quit" || input === "/exit") {
      console.log("\nGoodbye!");
      rl.close();
      return;
    }

    if (input === "/history") {
      console.log(`\nConversation: ${conversationHistory.length} messages`);
      console.log(`Agent: ${agentId}\n`);
      rl.prompt();
      return;
    }

    if (input === "/clear") {
      conversationHistory.length = 0;
      console.log("\nConversation cleared.\n");
      rl.prompt();
      return;
    }

    // Pause readline during processing
    rl.pause();

    try {
      const response = await runAgentLoop(input, conversationHistory, {
        llm,
        toolContext,
        onToolCall(name, toolInput) {
          const summary =
            name === "shell"
              ? `$ ${toolInput.command}`
              : name === "file_read"
                ? `reading ${toolInput.path}`
                : name === "file_write"
                  ? `writing ${toolInput.path}`
                  : name === "web_browse"
                    ? `fetching ${toolInput.url}`
                    : `${name}(${JSON.stringify(toolInput).slice(0, 80)})`;
          console.log(`  [tool] ${summary}`);
        },
        onToolResult(name, output, isError) {
          if (isError) {
            console.log(`  [tool] ${name}: ERROR - ${output.slice(0, 200)}`);
          } else {
            const preview = output.slice(0, 100).replace(/\n/g, " ");
            console.log(`  [tool] ${name}: ${preview}${output.length > 100 ? "..." : ""}`);
          }
        },
        onTokenUsage(inputTokens, outputTokens) {
          audit.log(agentId, "token_usage", "llm_call", "allowed", undefined, {
            inputTokens,
            outputTokens,
          });
        },
      });

      console.log(`\nagent> ${response.text}\n`);

      if (response.toolCallCount > 0) {
        console.log(
          `  [stats] ${response.iterations} iterations, ` +
          `${response.toolCallCount} tool calls, ` +
          `${response.totalInputTokens + response.totalOutputTokens} tokens\n`
        );
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`\n[error] ${msg}\n`);
      audit.log(agentId, "agent_error", msg, "blocked");
    }

    rl.resume();
    rl.prompt();
  });

  rl.on("close", () => {
    audit.log(agentId, "agent_stop", agentName, "allowed");
    audit.close();
    process.exit(0);
  });
}

// --- Main ---

async function main(): Promise<void> {
  if (!apiKey) {
    console.error(
      "[tamalebot-agent] Error: No API key found.\n" +
      "  Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, MOONSHOT_API_KEY,\n" +
      "  GOOGLE_API_KEY, MINIMAX_API_KEY, or TAMALEBOT_API_KEY"
    );
    process.exit(1);
  }

  const llm = new LLMClient({
    apiKey,
    provider: provider as import("./llm-client.js").LLMProvider | undefined,
    model,
    systemPrompt: buildSystemPrompt(),
  });

  const toolContext: ToolContext = {
    policy,
    audit,
    agentId,
    workDir,
  };

  console.log(`[tamalebot-agent] Agent "${agentName}" (${agentId}) starting`);
  console.log(`[tamalebot-agent] Provider: ${llm.getProvider()}`);
  console.log(`[tamalebot-agent] Model: ${llm.getModel()}`);
  console.log(`[tamalebot-agent] Policy: ${policyName}`);
  console.log(`[tamalebot-agent] Work dir: ${workDir}`);
  console.log(`[tamalebot-agent] Mode: ${mode}`);

  audit.log(agentId, "agent_start", agentName, "allowed", undefined, {
    model: llm.getModel(),
    policy: policyName,
    mode,
  });

  if (mode === "http") {
    await startHttpServer(llm, toolContext);
  } else {
    await startRepl(llm, toolContext);
  }
}

// Graceful shutdown (for REPL mode — HTTP mode handles its own)
if (mode !== "http") {
  process.on("SIGTERM", () => {
    console.log(`\n[tamalebot-agent] Agent ${agentId} shutting down`);
    audit.close();
    process.exit(0);
  });

  process.on("SIGINT", () => {
    // Let readline handle it
  });
}

main().catch((err) => {
  console.error(`[tamalebot-agent] Fatal error: ${err.message}`);
  audit.close();
  process.exit(1);
});
