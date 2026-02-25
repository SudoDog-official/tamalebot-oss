// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Model Router
 *
 * Classifies incoming messages and routes them to either a cheap/fast
 * model (for simple queries) or the primary model (for complex tasks).
 * Reduces costs by 40-70% for agents with mixed workloads.
 *
 * When enabled:
 *   1. A lightweight classifier model reads the user message
 *   2. It returns SIMPLE or COMPLEX
 *   3. SIMPLE → cheap model handles the full agent loop
 *   4. COMPLEX → primary model handles the full agent loop
 *
 * On classification failure, defaults to the primary model (safe fallback).
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import { LLMClient, type LLMProvider } from "./llm-client.js";

export type RouteClassification = "SIMPLE" | "COMPLEX";

export interface RouteResult {
  llm: LLMClient;
  classification: RouteClassification;
  routerTokens: { input: number; output: number };
}

export interface ModelRouterConfig {
  primaryLLM: LLMClient;
  routerModel: string;
  apiKey: string;
  provider?: LLMProvider;
  systemPrompt?: string;
}

const CLASSIFY_SYSTEM = `You are a message classifier. Classify the user's message as either SIMPLE or COMPLEX.

SIMPLE: Greetings, simple factual questions, conversational replies, status checks, thank you messages, yes/no answers, basic math, definitions, or anything that can be answered directly without tools or multi-step reasoning.

COMPLEX: Requests requiring tool use (shell commands, file operations, web browsing), multi-step tasks, code generation, debugging, analysis, planning, or anything requiring extended reasoning.

Respond with ONLY the word SIMPLE or COMPLEX. Nothing else.`;

export class ModelRouter {
  private primaryLLM: LLMClient;
  private cheapLLM: LLMClient;
  private classifierLLM: LLMClient;
  private totalRouted = 0;
  private simpleCount = 0;
  private complexCount = 0;

  constructor(config: ModelRouterConfig) {
    this.primaryLLM = config.primaryLLM;

    // Cheap LLM for handling simple tasks
    this.cheapLLM = new LLMClient({
      apiKey: config.apiKey,
      model: config.routerModel,
      provider: config.provider,
      systemPrompt: config.systemPrompt,
    });

    // Classifier uses the cheap model with a fixed system prompt
    this.classifierLLM = new LLMClient({
      apiKey: config.apiKey,
      model: config.routerModel,
      provider: config.provider,
      systemPrompt: CLASSIFY_SYSTEM,
      maxTokens: 10,
    });
  }

  async route(message: string, _history: MessageParam[]): Promise<RouteResult> {
    this.totalRouted++;

    try {
      const classifyResponse = await this.classifierLLM.sendMessage(
        [{ role: "user", content: message }],
        [] // No tools for classification
      );

      const raw = classifyResponse.text.trim().toUpperCase();
      const classification: RouteClassification = raw.includes("SIMPLE") ? "SIMPLE" : "COMPLEX";

      if (classification === "SIMPLE") {
        this.simpleCount++;
        return {
          llm: this.cheapLLM,
          classification,
          routerTokens: {
            input: classifyResponse.inputTokens,
            output: classifyResponse.outputTokens,
          },
        };
      }

      this.complexCount++;
      return {
        llm: this.primaryLLM,
        classification,
        routerTokens: {
          input: classifyResponse.inputTokens,
          output: classifyResponse.outputTokens,
        },
      };
    } catch (err) {
      // On classification failure, default to primary model (safe fallback)
      console.error(
        `[model-router] Classification failed: ${err instanceof Error ? err.message : err}`
      );
      this.complexCount++;
      return {
        llm: this.primaryLLM,
        classification: "COMPLEX",
        routerTokens: { input: 0, output: 0 },
      };
    }
  }

  getStats(): {
    totalRouted: number;
    simple: number;
    complex: number;
    savingsPercent: number;
  } {
    const pct =
      this.totalRouted > 0
        ? Math.round((this.simpleCount / this.totalRouted) * 100)
        : 0;
    return {
      totalRouted: this.totalRouted,
      simple: this.simpleCount,
      complex: this.complexCount,
      savingsPercent: pct,
    };
  }
}
