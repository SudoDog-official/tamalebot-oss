// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Context Compressor
 *
 * When conversation history gets long, compresses older messages into
 * a summary to stay within context limits and reduce token costs.
 *
 * Strategy:
 *   - Keep the last N messages verbatim (recent context)
 *   - Summarize everything before that into a single message
 *   - Use a cheap/fast model for summarization when possible
 *
 * The summary replaces older messages in-place, so the conversation
 * array is mutated to keep downstream code simple.
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";
import type { LLMClient } from "./llm-client.js";

export interface CompressionConfig {
  /** Max messages to keep verbatim (default: 10) */
  maxVerbatimMessages?: number;
  /** Whether compression is enabled (default: true) */
  enabled?: boolean;
}

export interface CompressionResult {
  compressed: boolean;
  originalCount: number;
  finalCount: number;
  summarizedCount: number;
}

const DEFAULT_MAX_VERBATIM = 10;

const SUMMARIZE_PROMPT = `Summarize this conversation between a user and an AI agent concisely. Include:
- Key tasks the user requested
- Important results or outputs from tool calls
- Any decisions or preferences the user expressed
- Current state of ongoing work

Be brief but preserve critical context. Do NOT include greetings or pleasantries.`;

/**
 * Compress conversation history by summarizing older messages.
 *
 * Mutates the history array in place — old messages are replaced
 * with a single summary message at the start.
 */
export async function compressHistory(
  history: MessageParam[],
  llm: LLMClient,
  config?: CompressionConfig
): Promise<CompressionResult> {
  const maxVerbatim = config?.maxVerbatimMessages ?? DEFAULT_MAX_VERBATIM;
  const enabled = config?.enabled ?? true;

  if (!enabled || history.length <= maxVerbatim) {
    return {
      compressed: false,
      originalCount: history.length,
      finalCount: history.length,
      summarizedCount: 0,
    };
  }

  // Split into old (to summarize) and recent (to keep)
  const splitAt = history.length - maxVerbatim;
  const oldMessages = history.slice(0, splitAt);
  const recentMessages = history.slice(splitAt);

  // Build a text representation of old messages for the summarizer
  const transcript = oldMessages
    .map((msg) => {
      const role = msg.role === "user" ? "User" : "Agent";
      if (typeof msg.content === "string") {
        return `${role}: ${msg.content}`;
      }
      // Array content — extract text and tool info
      if (Array.isArray(msg.content)) {
        const parts: string[] = [];
        for (const block of msg.content) {
          if (typeof block === "object" && "type" in block) {
            const b = block as unknown as Record<string, unknown>;
            if (b.type === "text") {
              parts.push(b.text as string);
            } else if (b.type === "tool_use") {
              parts.push(`[tool: ${b.name}(${JSON.stringify(b.input).slice(0, 100)})]`);
            } else if (b.type === "tool_result") {
              const content = (b.content as string) ?? "";
              parts.push(`[result: ${content.slice(0, 200)}]`);
            }
          }
        }
        return `${role}: ${parts.join(" ")}`;
      }
      return `${role}: [complex content]`;
    })
    .join("\n");

  // Send to LLM for summarization
  try {
    const response = await llm.sendMessage(
      [{ role: "user", content: `${SUMMARIZE_PROMPT}\n\n---\n\n${transcript}` }],
      [] // No tools for summarization
    );

    const summary = response.text || "[Earlier conversation context was summarized but no summary was generated]";

    // Mutate history in place: clear and rebuild
    history.length = 0;
    history.push({
      role: "user",
      content: `[Context from earlier in this conversation]\n${summary}`,
    });
    history.push({
      role: "assistant",
      content: "Understood, I have the context from our earlier conversation. How can I continue helping you?",
    });
    history.push(...recentMessages);

    return {
      compressed: true,
      originalCount: oldMessages.length + recentMessages.length,
      finalCount: history.length,
      summarizedCount: oldMessages.length,
    };
  } catch (err) {
    // If summarization fails, don't lose messages — just skip compression
    console.error(
      `[context-compressor] Summarization failed: ${err instanceof Error ? err.message : err}`
    );
    return {
      compressed: false,
      originalCount: history.length,
      finalCount: history.length,
      summarizedCount: 0,
    };
  }
}
