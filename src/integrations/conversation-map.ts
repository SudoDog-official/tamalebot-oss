// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Bounded Conversation Map
 *
 * A Map wrapper that limits the number of stored conversations
 * and the number of messages per conversation, preventing
 * unbounded memory growth in long-running integrations.
 *
 * Uses LRU eviction: when maxConversations is reached, the
 * least recently used conversation is evicted.
 */

import type { MessageParam } from "@anthropic-ai/sdk/resources/messages.js";

export interface ConversationMapOptions {
  /** Max number of concurrent conversations (default: 1000) */
  maxConversations?: number;
  /** Max messages per conversation (default: 200) */
  maxMessagesPerConversation?: number;
}

export class BoundedConversationMap<K = string | number> {
  private map = new Map<K, MessageParam[]>();
  private accessOrder: K[] = [];
  private maxConversations: number;
  private maxMessages: number;

  constructor(opts?: ConversationMapOptions) {
    this.maxConversations = opts?.maxConversations ?? 1000;
    this.maxMessages = opts?.maxMessagesPerConversation ?? 200;
  }

  get(key: K): MessageParam[] | undefined {
    const history = this.map.get(key);
    if (history) {
      this.touch(key);
    }
    return history;
  }

  getOrCreate(key: K): MessageParam[] {
    let history = this.map.get(key);
    if (!history) {
      this.evictIfNeeded();
      history = [];
      this.map.set(key, history);
    }
    this.touch(key);
    return history;
  }

  set(key: K, value: MessageParam[]): void {
    if (!this.map.has(key)) {
      this.evictIfNeeded();
    }
    // Trim to max messages if needed
    if (value.length > this.maxMessages) {
      value.splice(0, value.length - this.maxMessages);
    }
    this.map.set(key, value);
    this.touch(key);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  delete(key: K): boolean {
    this.accessOrder = this.accessOrder.filter(k => k !== key);
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
    this.accessOrder = [];
  }

  get size(): number {
    return this.map.size;
  }

  values(): IterableIterator<MessageParam[]> {
    return this.map.values();
  }

  /** Trim a specific conversation to maxMessages */
  trimConversation(key: K): void {
    const history = this.map.get(key);
    if (history && history.length > this.maxMessages) {
      history.splice(0, history.length - this.maxMessages);
    }
  }

  private touch(key: K): void {
    const idx = this.accessOrder.indexOf(key);
    if (idx !== -1) {
      this.accessOrder.splice(idx, 1);
    }
    this.accessOrder.push(key);
  }

  private evictIfNeeded(): void {
    while (this.map.size >= this.maxConversations && this.accessOrder.length > 0) {
      const oldest = this.accessOrder.shift()!;
      this.map.delete(oldest);
    }
  }
}
