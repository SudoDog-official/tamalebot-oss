// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Audit Trail
 *
 * Append-only JSONL log of every action an agent takes. Every tool call,
 * every LLM decision, every blocked action — all logged with timestamps
 * and agent IDs for forensics and compliance.
 */

import { createWriteStream, existsSync, mkdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";

export interface AuditEntry {
  timestamp: string;
  entryId: string;
  agentId: string;
  actionType: string;
  target: string;
  decision: "allowed" | "blocked";
  reason?: string;
  metadata?: Record<string, unknown>;
}

export class AuditTrail {
  private logPath: string;
  private stream: ReturnType<typeof createWriteStream> | null = null;

  constructor(logDir: string, agentId: string) {
    mkdirSync(logDir, { recursive: true });
    this.logPath = join(logDir, `${agentId}.audit.jsonl`);
  }

  private getStream(): ReturnType<typeof createWriteStream> {
    if (!this.stream) {
      this.stream = createWriteStream(this.logPath, { flags: "a" });
    }
    return this.stream;
  }

  private generateId(content: string, timestamp: string): string {
    return createHash("sha256")
      .update(`${timestamp}:${content}`)
      .digest("hex")
      .slice(0, 16);
  }

  log(
    agentId: string,
    actionType: string,
    target: string,
    decision: "allowed" | "blocked",
    reason?: string,
    metadata?: Record<string, unknown>
  ): string {
    const timestamp = new Date().toISOString();
    const entryId = this.generateId(`${actionType}:${target}`, timestamp);

    const entry: AuditEntry = {
      timestamp,
      entryId,
      agentId,
      actionType,
      target,
      decision,
      reason,
      metadata,
    };

    this.getStream().write(JSON.stringify(entry) + "\n");
    return entryId;
  }

  async getEntries(options?: {
    limit?: number;
    agentId?: string;
    decision?: "allowed" | "blocked";
  }): Promise<AuditEntry[]> {
    if (!existsSync(this.logPath)) return [];

    const content = await readFile(this.logPath, "utf-8");
    let entries: AuditEntry[] = content
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => {
        try {
          return JSON.parse(line) as AuditEntry;
        } catch {
          return null;
        }
      })
      .filter((entry): entry is AuditEntry => entry !== null);

    if (options?.agentId) {
      entries = entries.filter((e) => e.agentId === options.agentId);
    }
    if (options?.decision) {
      entries = entries.filter((e) => e.decision === options.decision);
    }
    if (options?.limit) {
      entries = entries.slice(-options.limit);
    }

    return entries;
  }

  close(): void {
    if (this.stream) {
      this.stream.end();
      this.stream = null;
    }
  }
}
