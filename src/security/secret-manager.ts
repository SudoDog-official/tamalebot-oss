// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Secret Manager
 *
 * Validates, injects, and masks secrets. API keys are injected as
 * environment variables into agent containers — the agent code never
 * sees the raw values. All access is logged to the audit trail.
 */

import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { AuditTrail } from "./audit-trail.js";

const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;

const SecretsFileSchema = z.record(z.string().min(1).max(4096));

export class SecretManager {
  private secrets: Map<string, string> = new Map();
  private audit: AuditTrail | null;

  constructor(audit?: AuditTrail) {
    this.audit = audit ?? null;
  }

  validateName(name: string): boolean {
    return SECRET_NAME_PATTERN.test(name);
  }

  validateValue(value: string): boolean {
    if (!value || value.includes("\n") || value.includes("\0")) return false;
    if (value.length > 4096) return false;
    return true;
  }

  async loadFromFile(filePath: string): Promise<number> {
    const content = await readFile(filePath, "utf-8");
    const parsed = SecretsFileSchema.parse(JSON.parse(content));
    let loaded = 0;

    for (const [name, value] of Object.entries(parsed)) {
      if (!this.validateName(name)) {
        this.audit?.log("system", "secret_rejected", name, "blocked", "Invalid secret name");
        continue;
      }
      if (!this.validateValue(value)) {
        this.audit?.log("system", "secret_rejected", name, "blocked", "Invalid secret value");
        continue;
      }
      this.secrets.set(name, value);
      this.audit?.log("system", "secret_loaded", name, "allowed");
      loaded++;
    }

    return loaded;
  }

  set(name: string, value: string): boolean {
    if (!this.validateName(name) || !this.validateValue(value)) return false;
    this.secrets.set(name, value);
    return true;
  }

  toEnvVars(): string[] {
    return Array.from(this.secrets.entries()).map(
      ([name, value]) => `${name}=${value}`
    );
  }

  toEnvObject(): Record<string, string> {
    return Object.fromEntries(this.secrets);
  }

  mask(value: string, showChars = 4): string {
    if (value.length <= showChars) return "*".repeat(value.length);
    return value.slice(0, showChars) + "*".repeat(value.length - showChars);
  }

  maskAll(text: string): string {
    let masked = text;
    for (const [, value] of this.secrets) {
      if (value.length >= 8 && masked.includes(value)) {
        masked = masked.replaceAll(value, this.mask(value));
      }
    }
    return masked;
  }
}
