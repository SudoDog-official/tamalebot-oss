// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

import { readFile } from "node:fs/promises";
import YAML from "yaml";
import type { PolicyConfig } from "../security/policy-engine.js";
import { DEFAULT_POLICY } from "../security/policy-engine.js";

export interface TamaleBotConfig {
  agent: {
    name: string;
    description?: string;
  };
  llm?: {
    provider: string;
    model: string;
  };
  policy?: PolicyConfig;
  integrations?: Record<string, Record<string, string>>;
}

export async function loadConfig(
  configPath: string
): Promise<TamaleBotConfig | null> {
  try {
    const content = await readFile(configPath, "utf-8");
    return YAML.parse(content) as TamaleBotConfig;
  } catch {
    // No config file is fine — use defaults
    return null;
  }
}
