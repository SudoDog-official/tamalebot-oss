// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * `tamalebot agent` command
 *
 * Starts an interactive AI agent in the terminal. The agent connects
 * to Claude, has access to tools (shell, files, web), and enforces
 * security policies on every action.
 *
 * Usage:
 *   tamalebot agent                    # Interactive chat mode
 *   tamalebot agent --telegram         # Telegram bot mode
 *   tamalebot agent --name "My Bot"    # Custom agent name
 */

import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import { PolicyEngine, DEFAULT_POLICY } from "../../security/policy-engine.js";
import { AuditTrail } from "../../security/audit-trail.js";
import { LLMClient } from "../../agent/llm-client.js";
import { TelegramIntegration } from "../../integrations/telegram.js";
import { loadConfig } from "../config.js";
import type { ToolContext } from "../../agent/tools.js";

interface AgentOptions {
  config: string;
  name?: string;
  model?: string;
  telegram?: boolean;
}

export async function agentCommand(options: AgentOptions): Promise<void> {
  const agentId = randomUUID().slice(0, 8);
  const logDir = join(homedir(), ".tamalebot", "logs");
  const config = await loadConfig(options.config);

  const agentName = options.name ?? config?.agent?.name ?? "TamaleBot Agent";
  const modelId = options.model ?? config?.llm?.model ?? undefined;

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error(chalk.red("\n  Error: ANTHROPIC_API_KEY not set.\n"));
    console.log(chalk.dim("  Set it with: export ANTHROPIC_API_KEY=sk-ant-..."));
    console.log(chalk.dim("  Or add it to your .env file.\n"));
    process.exit(1);
  }

  const policy = new PolicyEngine(config?.policy ?? DEFAULT_POLICY);
  const audit = new AuditTrail(logDir, agentId);

  const systemPrompt =
    `You are ${agentName}, a helpful AI agent powered by TamaleBot. ` +
    `You can execute shell commands, read and write files, and browse the web.\n\n` +
    `Guidelines:\n` +
    `- Use the tools available to you to accomplish tasks\n` +
    `- Always explain what you're doing before taking actions\n` +
    `- If a tool call is blocked by security policy, explain what happened and suggest alternatives\n` +
    `- Be concise and direct in your responses`;

  const llm = new LLMClient({
    apiKey,
    model: modelId,
    systemPrompt,
  });

  const toolContext: ToolContext = {
    policy,
    audit,
    agentId,
    workDir: process.cwd(),
  };

  console.log(chalk.bold(`\n  TamaleBot Agent: ${agentName}`));
  console.log(chalk.dim(`  ID: ${agentId}`));
  console.log(chalk.dim(`  Model: ${llm.getModel()}`));
  console.log(chalk.dim(`  Logs: ${logDir}/${agentId}.audit.jsonl`));

  audit.log(agentId, "agent_start", agentName, "allowed", undefined, {
    model: llm.getModel(),
    mode: options.telegram ? "telegram" : "interactive",
  });

  if (options.telegram) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) {
      console.error(chalk.red("\n  Error: TELEGRAM_BOT_TOKEN not set.\n"));
      console.log(chalk.dim("  Get a token from @BotFather on Telegram."));
      console.log(chalk.dim("  Set it with: export TELEGRAM_BOT_TOKEN=your-token\n"));
      audit.close();
      process.exit(1);
    }

    const telegram = new TelegramIntegration({
      botToken,
      llm,
      toolContext,
    });

    console.log(chalk.dim("  Mode: Telegram bot"));
    console.log("");

    await telegram.connect();

    // Keep the process alive
    process.on("SIGINT", async () => {
      console.log(chalk.dim("\n  Shutting down..."));
      await telegram.disconnect();
      audit.log(agentId, "agent_stop", agentName, "allowed");
      audit.close();
      process.exit(0);
    });

    process.on("SIGTERM", async () => {
      await telegram.disconnect();
      audit.log(agentId, "agent_stop", agentName, "allowed");
      audit.close();
      process.exit(0);
    });
  } else {
    // Interactive mode — launch the agent runtime
    console.log(chalk.dim("  Mode: Interactive chat"));
    console.log(chalk.dim("  Commands: /clear, /history, /quit\n"));

    // Import and run the interactive agent
    const { createInterface } = await import("node:readline");
    const { runAgentLoop } = await import("../../agent/agent-loop.js");

    const conversationHistory: Array<{ role: string; content: any }> = [];

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: chalk.green("you> "),
    });

    rl.prompt();

    rl.on("line", async (line) => {
      const input = line.trim();
      if (!input) {
        rl.prompt();
        return;
      }

      if (input === "/quit" || input === "/exit") {
        rl.close();
        return;
      }

      if (input === "/history") {
        console.log(chalk.dim(`\n  ${conversationHistory.length} messages in conversation\n`));
        rl.prompt();
        return;
      }

      if (input === "/clear") {
        conversationHistory.length = 0;
        console.log(chalk.dim("\n  Conversation cleared.\n"));
        rl.prompt();
        return;
      }

      rl.pause();

      try {
        const response = await runAgentLoop(input, conversationHistory as any, {
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
            console.log(chalk.dim(`  [tool] ${summary}`));
          },
          onToolResult(name, output, isError) {
            if (isError) {
              console.log(chalk.red(`  [tool] ${name}: ${output.slice(0, 200)}`));
            } else {
              const preview = output.slice(0, 120).replace(/\n/g, " ");
              console.log(chalk.dim(`  [tool] ${name}: ${preview}${output.length > 120 ? "..." : ""}`));
            }
          },
        });

        console.log(chalk.cyan(`\nagent> `) + response.text + "\n");

        if (response.toolCallCount > 0) {
          console.log(
            chalk.dim(
              `  [${response.iterations} iterations, ` +
              `${response.toolCallCount} tools, ` +
              `${response.totalInputTokens + response.totalOutputTokens} tokens]\n`
            )
          );
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`\n  Error: ${msg}\n`));
      }

      rl.resume();
      rl.prompt();
    });

    rl.on("close", () => {
      console.log(chalk.dim("\n  Goodbye!\n"));
      audit.log(agentId, "agent_stop", agentName, "allowed");
      audit.close();
      process.exit(0);
    });
  }
}
