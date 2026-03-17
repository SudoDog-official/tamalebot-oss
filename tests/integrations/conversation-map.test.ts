// SPDX-License-Identifier: Apache-2.0
/**
 * BoundedConversationMap Tests
 *
 * Validates LRU eviction, max message limits, and conversation lifecycle.
 */

import { describe, it, expect } from "vitest";
import { BoundedConversationMap } from "../../src/integrations/conversation-map.js";

describe("BoundedConversationMap", () => {
  it("should store and retrieve conversations", () => {
    const map = new BoundedConversationMap();
    const history = map.getOrCreate("chat-1");
    history.push({ role: "user", content: "hello" });
    history.push({ role: "assistant", content: "hi" });

    expect(map.get("chat-1")?.length).toBe(2);
  });

  it("should return undefined for missing keys", () => {
    const map = new BoundedConversationMap();
    expect(map.get("nonexistent")).toBeUndefined();
  });

  it("should evict oldest conversation when maxConversations exceeded", () => {
    const map = new BoundedConversationMap({ maxConversations: 3 });

    map.getOrCreate("a");
    map.getOrCreate("b");
    map.getOrCreate("c");
    expect(map.size).toBe(3);

    // Adding a 4th should evict "a" (oldest)
    map.getOrCreate("d");
    expect(map.size).toBe(3);
    expect(map.has("a")).toBe(false);
    expect(map.has("b")).toBe(true);
    expect(map.has("d")).toBe(true);
  });

  it("should use LRU order for eviction", () => {
    const map = new BoundedConversationMap({ maxConversations: 3 });

    map.getOrCreate("a");
    map.getOrCreate("b");
    map.getOrCreate("c");

    // Touch "a" to make it recently used
    map.get("a");

    // Adding "d" should evict "b" (least recently used)
    map.getOrCreate("d");
    expect(map.has("a")).toBe(true);  // Recently touched
    expect(map.has("b")).toBe(false); // Evicted (LRU)
    expect(map.has("c")).toBe(true);
    expect(map.has("d")).toBe(true);
  });

  it("should trim messages when set exceeds maxMessages", () => {
    const map = new BoundedConversationMap({ maxMessagesPerConversation: 4 });
    const messages = Array.from({ length: 10 }, (_, i) => ({
      role: "user" as const,
      content: `msg-${i}`,
    }));

    map.set("chat", messages);
    const stored = map.get("chat")!;
    expect(stored.length).toBe(4);
    // Should keep the LAST 4 messages
    expect(stored[0].content).toBe("msg-6");
    expect(stored[3].content).toBe("msg-9");
  });

  it("should delete conversations", () => {
    const map = new BoundedConversationMap();
    map.getOrCreate("to-delete");
    expect(map.has("to-delete")).toBe(true);

    map.delete("to-delete");
    expect(map.has("to-delete")).toBe(false);
    expect(map.size).toBe(0);
  });

  it("should clear all conversations", () => {
    const map = new BoundedConversationMap();
    map.getOrCreate("a");
    map.getOrCreate("b");
    map.getOrCreate("c");

    map.clear();
    expect(map.size).toBe(0);
  });

  it("should work with numeric keys", () => {
    const map = new BoundedConversationMap<number>({ maxConversations: 2 });
    map.getOrCreate(123);
    map.getOrCreate(456);
    expect(map.size).toBe(2);

    map.getOrCreate(789);
    expect(map.size).toBe(2);
    expect(map.has(123)).toBe(false);
  });

  it("should not evict when updating existing key", () => {
    const map = new BoundedConversationMap({ maxConversations: 2 });
    map.getOrCreate("a");
    map.getOrCreate("b");

    // Accessing "a" again should not trigger eviction
    map.getOrCreate("a");
    expect(map.size).toBe(2);
    expect(map.has("a")).toBe(true);
    expect(map.has("b")).toBe(true);
  });
});
