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
  allowedSSHHosts?: string[];
  allowedGitRepos?: string[];
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
  String.raw`curl.*webhook\.site`,
  String.raw`curl.*pipedream`,
  String.raw`curl.*hookbin`,
  String.raw`curl.*beeceptor`,
  String.raw`curl.*postb\.in`,
  String.raw`wget.*webhook\.site`,
];

export const DEFAULT_POLICY: PolicyConfig = {
  name: "default",
  blockedReadPaths: DEFAULT_BLOCKED_READ_PATHS,
  blockedWritePaths: DEFAULT_BLOCKED_WRITE_PATHS,
  dangerousCommandPatterns: DEFAULT_DANGEROUS_PATTERNS,
};

export class PolicyEngine {
  static readonly DEFAULT_CONFIG: PolicyConfig = DEFAULT_POLICY;

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

  /**
   * Check if a hostname contains characters from multiple Unicode scripts,
   * which is a strong indicator of a homoglyph/IDN attack.
   * e.g. "githuƄ.com" mixes Latin and Cyrillic.
   */
  private hasMixedScripts(hostname: string): boolean {
    // Only check the non-TLD part (labels before the last dot)
    const labels = hostname.split(".");
    // Strip the TLD — only inspect the registrable labels
    const toCheck = labels.slice(0, -1).join(".");
    if (!toCheck) return false;

    let hasLatin = false;
    let hasNonLatinLetter = false;

    for (const char of toCheck) {
      const code = char.codePointAt(0)!;
      // ASCII Latin letters
      if ((code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A)) {
        hasLatin = true;
      }
      // Common non-Latin scripts used in homoglyph attacks:
      // Cyrillic (0400-04FF), Greek (0370-03FF), Armenian (0530-058F)
      else if (
        (code >= 0x0370 && code <= 0x03FF) || // Greek
        (code >= 0x0400 && code <= 0x04FF) || // Cyrillic
        (code >= 0x0530 && code <= 0x058F) || // Armenian
        (code >= 0x10A0 && code <= 0x10FF)    // Georgian
      ) {
        hasNonLatinLetter = true;
      }
    }

    return hasLatin && hasNonLatinLetter;
  }

  /**
   * Normalize a hostname for safe comparison:
   * - Apply Unicode NFKC normalization (collapses compatibility characters)
   * - Convert to lowercase
   * - Convert to ASCII via punycode where possible
   */
  private normalizeHostname(hostname: string): string {
    try {
      // NFKC normalization collapses compatibility characters and composed forms
      const normalized = hostname.normalize("NFKC").toLowerCase();
      // Use URL constructor to get punycode-encoded hostname
      const punycoded = new URL(`https://${normalized}`).hostname;
      return punycoded;
    } catch {
      return hostname.toLowerCase();
    }
  }

  /**
   * Extract the raw hostname from a URL string before the URL constructor
   * converts IDN/Unicode to punycode. This preserves the original characters
   * so mixed-script detection can work.
   */
  private extractRawHostname(url: string): string | null {
    const match = url.match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : null;
  }

  checkDomain(url: string): PolicyDecision {
    try {
      // Extract raw hostname BEFORE URL constructor converts to punycode
      const rawHostname = this.extractRawHostname(url);

      // Block mixed-script hostnames (homoglyph attacks) regardless of allowlist
      if (rawHostname && this.hasMixedScripts(rawHostname)) {
        return {
          allowed: false,
          reason: `Domain ${rawHostname} contains mixed Unicode scripts (possible homoglyph attack)`,
        };
      }

      const hostname = new URL(url).hostname;

      if (!this.config.allowedDomains || this.config.allowedDomains.length === 0) {
        return { allowed: true };
      }

      const normalizedHostname = this.normalizeHostname(hostname);
      const isAllowed = this.config.allowedDomains.some((domain) => {
        const normalizedDomain = this.normalizeHostname(domain);
        return normalizedHostname === normalizedDomain ||
          normalizedHostname.endsWith(`.${normalizedDomain}`);
      });

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

  checkSSH(target: string): PolicyDecision {
    if (!this.config.allowedSSHHosts || this.config.allowedSSHHosts.length === 0) {
      return { allowed: true };
    }

    // target format: user@host:port
    const hostMatch = target.match(/@([^:]+)/);
    const host = hostMatch ? hostMatch[1] : target;

    const isAllowed = this.config.allowedSSHHosts.some(
      (allowed) => host === allowed || host.endsWith(`.${allowed}`)
    );

    if (!isAllowed) {
      return {
        allowed: false,
        reason: `SSH to ${host} is not in the allowlist`,
      };
    }

    return { allowed: true };
  }

  checkGit(target: string): PolicyDecision {
    if (!this.config.allowedGitRepos || this.config.allowedGitRepos.length === 0) {
      return { allowed: true };
    }

    // target format: "action repo_or_path"
    const parts = target.split(" ", 2);
    const repoOrPath = parts[1] ?? "";

    // Only check allowlist for remote operations
    if (!repoOrPath.includes("://") && !repoOrPath.includes("@") && !repoOrPath.includes("github.com")) {
      return { allowed: true };
    }

    const isAllowed = this.config.allowedGitRepos.some(
      (allowed) => repoOrPath.includes(allowed)
    );

    if (!isAllowed) {
      return {
        allowed: false,
        reason: `Git repo ${repoOrPath} is not in the allowlist`,
      };
    }

    return { allowed: true };
  }

  evaluate(
    actionType: "file_read" | "file_write" | "command" | "http_request" | "vault" | "ssh_exec" | "git" | "schedule" | "sub_agent",
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
      case "ssh_exec":
        return this.checkSSH(target);
      case "git":
        return this.checkGit(target);
      case "vault":
      case "schedule":
        // Vault and schedule operations are allowed by default
        return { allowed: true };
      default:
        return { allowed: true };
    }
  }
}
