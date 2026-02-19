// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

import { writeFile, access } from "node:fs/promises";
import chalk from "chalk";

const DEFAULT_CONFIG = `# TamaleBot Agent Configuration
# https://github.com/SudoDog-official/TamaleBot

agent:
  name: my-agent
  description: ""

# LLM provider (bring your own API key)
llm:
  provider: anthropic  # anthropic | openai | google
  model: claude-sonnet-4-5-20250929
  # API key is read from environment: ANTHROPIC_API_KEY

# Security policy
policy:
  name: default
  # Uncomment to customize:
  # allowed_domains:
  #   - api.anthropic.com
  #   - api.openai.com
  # max_requests_per_minute: 60

# Integrations (Phase 2)
# integrations:
#   telegram:
#     bot_token_env: TELEGRAM_BOT_TOKEN
#   slack:
#     app_token_env: SLACK_APP_TOKEN
`;

interface InitOptions {
  template?: string;
}

export async function initCommand(options: InitOptions): Promise<void> {
  const configPath = "tamalebot.yaml";

  try {
    await access(configPath);
    console.log(chalk.yellow(`\n  ${configPath} already exists. Skipping.\n`));
    return;
  } catch {
    // File doesn't exist, proceed
  }

  await writeFile(configPath, DEFAULT_CONFIG, "utf-8");
  console.log(chalk.green(`\n  Created ${configPath}\n`));
  console.log(chalk.dim("  Next steps:"));
  console.log(chalk.dim("  1. Set your API key: export ANTHROPIC_API_KEY=sk-..."));
  console.log(chalk.dim("  2. Run an agent:     tamalebot run python my_agent.py"));
  console.log(chalk.dim("  3. View audit trail: cat ~/.tamalebot/logs/*.audit.jsonl\n"));
}
