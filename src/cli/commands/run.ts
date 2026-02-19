// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import { PolicyEngine, DEFAULT_POLICY } from "../../security/policy-engine.js";
import { AuditTrail } from "../../security/audit-trail.js";
import { loadConfig } from "../config.js";

interface RunOptions {
  config: string;
  policy: string;
  docker?: boolean;
  dryRun?: boolean;
}

export async function runCommand(
  commandArgs: string[],
  options: RunOptions
): Promise<void> {
  const agentId = randomUUID().slice(0, 8);
  const logDir = join(homedir(), ".tamalebot", "logs");
  const config = await loadConfig(options.config);

  const policy = new PolicyEngine(config?.policy ?? DEFAULT_POLICY);
  const audit = new AuditTrail(logDir, agentId);

  const command = commandArgs.join(" ");

  if (!command) {
    console.log(chalk.red("Error: No command specified."));
    console.log(chalk.dim("Usage: tamalebot run <command>"));
    console.log(chalk.dim("Example: tamalebot run python my_agent.py"));
    process.exit(1);
  }

  // Pre-execution security check
  const decision = policy.evaluate("command", command);

  audit.log(agentId, "command", command, decision.allowed ? "allowed" : "blocked", decision.reason);

  if (!decision.allowed) {
    console.log(chalk.red(`\n  BLOCKED: ${decision.reason}\n`));
    console.log(chalk.dim(`  Agent: ${agentId}`));
    console.log(chalk.dim(`  Audit: ${logDir}/${agentId}.audit.jsonl`));
    audit.close();
    process.exit(1);
  }

  if (options.dryRun) {
    console.log(chalk.green(`\n  ALLOWED: Command passed security checks\n`));
    console.log(chalk.dim(`  Command: ${command}`));
    console.log(chalk.dim(`  Policy: ${options.policy}`));
    audit.close();
    return;
  }

  // Run the command
  console.log(chalk.dim(`[tamalebot] Agent ${agentId} starting`));
  console.log(chalk.dim(`[tamalebot] Policy: ${options.policy}`));
  console.log(chalk.dim(`[tamalebot] Audit: ${logDir}/${agentId}.audit.jsonl\n`));

  const child = spawn(command, {
    shell: true,
    stdio: "inherit",
    env: {
      ...process.env,
      TAMALEBOT_AGENT_ID: agentId,
      TAMALEBOT_POLICY: options.policy,
    },
  });

  child.on("exit", (code) => {
    audit.log(agentId, "process_exit", command, "allowed", undefined, {
      exitCode: code,
    });
    audit.close();
    console.log(
      chalk.dim(`\n[tamalebot] Agent ${agentId} exited with code ${code}`)
    );
    process.exit(code ?? 0);
  });

  child.on("error", (err) => {
    audit.log(agentId, "process_error", command, "allowed", err.message);
    audit.close();
    console.error(chalk.red(`\n[tamalebot] Error: ${err.message}`));
    process.exit(1);
  });
}
