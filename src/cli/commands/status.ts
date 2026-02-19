// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

import chalk from "chalk";

interface StatusOptions {
  agent?: string;
}

export async function statusCommand(options: StatusOptions): Promise<void> {
  console.log(chalk.bold("\nTamaleBot Agent Status\n"));

  if (options.agent) {
    console.log(chalk.dim(`Agent ${options.agent}: not yet implemented`));
  } else {
    console.log(chalk.dim("No agents running."));
    console.log(
      chalk.dim("Start one with: tamalebot run <command>")
    );
  }
}
