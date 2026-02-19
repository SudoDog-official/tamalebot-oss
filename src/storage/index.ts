// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Storage Abstraction
 *
 * Provides a unified interface over different storage backends.
 * The agent code calls these methods; the backend is swapped
 * based on deployment target.
 *
 * Backends:
 *   - Cloudflare R2 (default for hosted)
 *   - AWS S3
 *   - MinIO (self-hosted)
 *   - Local filesystem (development)
 *
 * All backends speak S3-compatible API, making migration trivial.
 */

export interface StorageBackend {
  put(key: string, data: Buffer | string): Promise<void>;
  get(key: string): Promise<Buffer | null>;
  delete(key: string): Promise<void>;
  list(prefix?: string): Promise<string[]>;
}

export class LocalStorage implements StorageBackend {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  async put(key: string, data: Buffer | string): Promise<void> {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { join, dirname } = await import("node:path");
    const fullPath = join(this.basePath, key);
    await mkdir(dirname(fullPath), { recursive: true });
    await writeFile(fullPath, data);
  }

  async get(key: string): Promise<Buffer | null> {
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    try {
      return await readFile(join(this.basePath, key));
    } catch {
      return null;
    }
  }

  async delete(key: string): Promise<void> {
    const { unlink } = await import("node:fs/promises");
    const { join } = await import("node:path");
    try {
      await unlink(join(this.basePath, key));
    } catch {
      // File already gone
    }
  }

  async list(prefix?: string): Promise<string[]> {
    const { readdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    try {
      const dir = prefix ? join(this.basePath, prefix) : this.basePath;
      return await readdir(dir);
    } catch {
      return [];
    }
  }
}
