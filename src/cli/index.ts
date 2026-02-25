#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

import { Command } from "commander";
import { runCommand } from "./commands/run.js";
import { statusCommand } from "./commands/status.js";
import { initCommand } from "./commands/init.js";
import { agentCommand } from "./commands/agent.js";

const program = new Command();

program
  .name("tamalebot")
  .description(
    "Security-first AI agent platform. Isolated agents, any cloud, full audit trail."
  )
  .version("0.1.0");

program
  .command("run")
  .description("Start an agent with security policies applied")
  .argument("[command...]", "Command to wrap and monitor")
  .option("-c, --config <path>", "Path to agent config file", "tamalebot.yaml")
  .option("-p, --policy <name>", "Security policy to apply", "default")
  .option("--docker", "Run inside a Docker sandbox")
  .option("--dry-run", "Show what would be blocked without executing")
  .action(runCommand);

program
  .command("init")
  .description("Initialize a new TamaleBot agent configuration")
  .option("-t, --template <name>", "Agent template to use")
  .action(initCommand);

program
  .command("status")
  .description("Show running agents and their status")
  .option("-a, --agent <id>", "Show status of a specific agent")
  .action(statusCommand);

program
  .command("agent")
  .description("Start an interactive AI agent")
  .option("-c, --config <path>", "Path to agent config file", "tamalebot.yaml")
  .option("-n, --name <name>", "Agent name")
  .option("-m, --model <model>", "LLM model to use")
  .option("--telegram", "Run as a Telegram bot")
  .action(agentCommand);

program.parse();
