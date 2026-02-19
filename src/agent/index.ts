// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Agent Runtime
 *
 * This is the process that runs inside each agent's Docker container
 * (or locally via `tamalebot run`). It:
 * 1. Connects to the Claude API
 * 2. Accepts messages (from stdin in standalone mode, or via integration)
 * 3. Runs the tool-use loop with security policy enforcement
 * 4. Returns responses
 */

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

const agentId = process.env.TAMALEBOT_AGENT_ID ?? "standalone";
const policyName = process.env.TAMALEBOT_POLICY ?? "default";
const apiKey = process.env.ANTHROPIC_API_KEY ?? "";
const model = process.env.TAMALEBOT_MODEL ?? undefined;
const agentName = process.env.TAMALEBOT_AGENT_NAME ?? "TamaleBot Agent";

// Determine log and work directories based on environment
const isDocker = process.env.TAMALEBOT_DOCKER === "true";
const logDir = isDocker ? "/app/data/logs" : join(homedir(), ".tamalebot", "logs");
const workDir = isDocker ? "/tmp/workspace" : process.cwd();

const policy = new PolicyEngine();
const audit = new AuditTrail(logDir, agentId);
const secrets = new SecretManager(audit);

const DEFAULT_SYSTEM_PROMPT = `You are ${agentName}, a helpful AI agent powered by TamaleBot. You can execute shell commands, read and write files, and browse the web.

Guidelines:
- Use the tools available to you to accomplish tasks
- Always explain what you're doing before taking actions
- If a tool call is blocked by security policy, explain what happened and suggest alternatives
- Be concise and direct in your responses
- If you're unsure about something, say so rather than guessing`;

async function main(): Promise<void> {
  if (!apiKey) {
    console.error(
      "[tamalebot-agent] Error: ANTHROPIC_API_KEY not set.\n" +
      "  Set it with: export ANTHROPIC_API_KEY=sk-ant-...\n" +
      "  Or add it to your .env file."
    );
    process.exit(1);
  }

  const llm = new LLMClient({
    apiKey,
    model,
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
  });

  const toolContext: ToolContext = {
    policy,
    audit,
    agentId,
    workDir,
  };

  console.log(`[tamalebot-agent] Agent "${agentName}" (${agentId}) starting`);
  console.log(`[tamalebot-agent] Model: ${llm.getModel()}`);
  console.log(`[tamalebot-agent] Policy: ${policyName}`);
  console.log(`[tamalebot-agent] Work dir: ${workDir}`);
  console.log(`[tamalebot-agent] Type a message to chat. Ctrl+C to exit.\n`);

  audit.log(agentId, "agent_start", agentName, "allowed", undefined, {
    model: llm.getModel(),
    policy: policyName,
  });

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
          // Token tracking for budget guard (Phase 1: just log it)
          audit.log(agentId, "token_usage", "llm_call", "allowed", undefined, {
            inputTokens,
            outputTokens,
          });
        },
      });

      console.log(`\nagent> ${response.text}\n`);

      // Log stats
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

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log(`\n[tamalebot-agent] Agent ${agentId} shutting down`);
  audit.close();
  process.exit(0);
});

process.on("SIGINT", () => {
  // Let readline handle it
});

main().catch((err) => {
  console.error(`[tamalebot-agent] Fatal error: ${err.message}`);
  audit.close();
  process.exit(1);
});
