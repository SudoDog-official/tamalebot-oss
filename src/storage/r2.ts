// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * R2 Storage Backend
 *
 * Accesses Cloudflare R2 via the Worker's HTTP API.
 * The container can't bind R2 directly, so it calls the Worker
 * which has the R2 binding.
 *
 * Worker routes:
 *   GET    /api/agent/:name/storage/:key     — read
 *   PUT    /api/agent/:name/storage/:key     — write
 *   DELETE /api/agent/:name/storage/:key     — delete
 *   GET    /api/agent/:name/storage?prefix=  — list
 */

import type { StorageBackend } from "./index.js";

export class R2Storage implements StorageBackend {
  private workerUrl: string;
  private agentName: string;

  constructor(workerUrl: string, agentName: string) {
    // Strip trailing slash
    this.workerUrl = workerUrl.replace(/\/$/, "");
    this.agentName = agentName;
  }

  private url(key: string): string {
    return `${this.workerUrl}/api/agent/${this.agentName}/storage/${key}`;
  }

  async put(key: string, data: Buffer | string): Promise<void> {
    const body = typeof data === "string" ? data : data.toString("utf-8");
    const res = await fetch(this.url(key), {
      method: "PUT",
      body,
    });
    if (!res.ok) {
      throw new Error(`R2 put failed (${res.status}): ${await res.text()}`);
    }
  }

  async get(key: string): Promise<Buffer | null> {
    const res = await fetch(this.url(key));
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`R2 get failed (${res.status}): ${await res.text()}`);
    }
    const text = await res.text();
    return Buffer.from(text, "utf-8");
  }

  async delete(key: string): Promise<void> {
    const res = await fetch(this.url(key), { method: "DELETE" });
    if (!res.ok && res.status !== 404) {
      throw new Error(`R2 delete failed (${res.status}): ${await res.text()}`);
    }
  }

  async list(prefix?: string): Promise<string[]> {
    const params = prefix ? `?prefix=${encodeURIComponent(prefix)}` : "";
    const res = await fetch(
      `${this.workerUrl}/api/agent/${this.agentName}/storage${params}`
    );
    if (!res.ok) {
      throw new Error(`R2 list failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { keys: string[] };
    return data.keys;
  }
}
