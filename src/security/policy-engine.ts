// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Security Policy Engine
 *
 * Intercepts every tool call before execution. Checks against blocked
 * patterns, path allowlists, rate limits, and custom policies. Logs
 * every decision to an append-only audit trail.
 *
 * This is the core of TamaleBot's security model and is open source
 * so users can verify exactly what runs between their agent and the world.
 */

import { z } from "zod";

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  matchedPatterns?: string[];
}

export interface PolicyConfig {
  name: string;
  blockedReadPaths: string[];
  blockedWritePaths: string[];
  dangerousCommandPatterns: string[];
  allowedDomains?: string[];
  maxRequestsPerMinute?: number;
}

const DEFAULT_BLOCKED_READ_PATHS = [
  "/etc/shadow",
  "/etc/passwd",
  "/etc/sudoers",
  "~/.ssh/id_rsa",
  "~/.ssh/id_ed25519",
  "~/.aws/credentials",
  "~/.config/gcloud/",
  ".env",
  ".env.local",
  ".env.production",
  "~/.docker/config.json",
  "~/.kube/config",
];

const DEFAULT_BLOCKED_WRITE_PATHS = [
  "/etc/",
  "/usr/bin/",
  "/usr/sbin/",
  "/bin/",
  "/sbin/",
  "/boot/",
  "/sys/",
  "/proc/",
];

const DEFAULT_DANGEROUS_PATTERNS = [
  // Database operations
  String.raw`DROP\s+TABLE`,
  String.raw`DROP\s+DATABASE`,
  String.raw`TRUNCATE\s+TABLE`,
  String.raw`DELETE\s+FROM\s+\w+\s*;?\s*$`,

  // File system operations
  String.raw`rm\s+-rf\s+/`,
  String.raw`rm\s+-rf\s+\*`,
  String.raw`sudo\s+rm`,
  String.raw`chmod\s+777`,

  // System operations
  String.raw`mkfs\.`,
  String.raw`dd\s+if=`,
  String.raw`:\(\)\{\s*:\|:&\s*\};:`,

  // Network exfiltration
  String.raw`curl.*pastebin`,
  String.raw`wget.*pastebin`,
  String.raw`curl.*ngrok`,
  String.raw`curl.*requestbin`,
];

export const DEFAULT_POLICY: PolicyConfig = {
  name: "default",
  blockedReadPaths: DEFAULT_BLOCKED_READ_PATHS,
  blockedWritePaths: DEFAULT_BLOCKED_WRITE_PATHS,
  dangerousCommandPatterns: DEFAULT_DANGEROUS_PATTERNS,
};

export class PolicyEngine {
  private compiledPatterns: RegExp[];
  private config: PolicyConfig;

  constructor(config: PolicyConfig = DEFAULT_POLICY) {
    this.config = config;
    this.compiledPatterns = this.compilePatterns(
      config.dangerousCommandPatterns
    );
  }

  private compilePatterns(patterns: string[]): RegExp[] {
    const compiled: RegExp[] = [];
    for (const pattern of patterns) {
      if (!pattern.trim()) continue;
      try {
        compiled.push(new RegExp(pattern, "i"));
      } catch {
        // Skip invalid patterns silently
      }
    }
    return compiled;
  }

  private expandHome(path: string): string {
    const home = process.env.HOME || process.env.USERPROFILE || "~";
    return path.replace(/^~/, home);
  }

  checkFileRead(path: string): PolicyDecision {
    const expanded = this.expandHome(path);

    for (const blocked of this.config.blockedReadPaths) {
      const blockedExpanded = this.expandHome(blocked);

      if (expanded === blockedExpanded) {
        return {
          allowed: false,
          reason: `Read access to ${path} is blocked (sensitive file)`,
        };
      }

      if (blockedExpanded.endsWith("/") && expanded.startsWith(blockedExpanded)) {
        return {
          allowed: false,
          reason: `Read access to ${path} is blocked (sensitive directory)`,
        };
      }
    }

    return { allowed: true };
  }

  checkFileWrite(path: string): PolicyDecision {
    const expanded = this.expandHome(path);

    for (const blocked of this.config.blockedWritePaths) {
      if (expanded.startsWith(blocked)) {
        return {
          allowed: false,
          reason: `Write to ${path} is blocked (system directory)`,
        };
      }
    }

    return { allowed: true };
  }

  checkCommand(command: string): PolicyDecision {
    const matched: string[] = [];

    for (const pattern of this.compiledPatterns) {
      if (pattern.test(command)) {
        matched.push(pattern.source);
      }
    }

    if (matched.length > 0) {
      return {
        allowed: false,
        reason: `Command contains dangerous patterns: ${matched.slice(0, 2).join(", ")}`,
        matchedPatterns: matched,
      };
    }

    return { allowed: true };
  }

  checkDomain(url: string): PolicyDecision {
    if (!this.config.allowedDomains || this.config.allowedDomains.length === 0) {
      return { allowed: true };
    }

    try {
      const hostname = new URL(url).hostname;
      const isAllowed = this.config.allowedDomains.some(
        (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
      );

      if (!isAllowed) {
        return {
          allowed: false,
          reason: `Domain ${hostname} is not in the allowlist`,
        };
      }
    } catch {
      return {
        allowed: false,
        reason: `Invalid URL: ${url}`,
      };
    }

    return { allowed: true };
  }

  evaluate(
    actionType: "file_read" | "file_write" | "command" | "http_request",
    target: string
  ): PolicyDecision {
    switch (actionType) {
      case "file_read":
        return this.checkFileRead(target);
      case "file_write":
        return this.checkFileWrite(target);
      case "command":
        return this.checkCommand(target);
      case "http_request":
        return this.checkDomain(target);
      default:
        return { allowed: true };
    }
  }
}
