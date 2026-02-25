// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { PolicyEngine } from "../../src/security/policy-engine.js";

describe("PolicyEngine", () => {
  const engine = new PolicyEngine();

  describe("command blocking", () => {
    it("blocks rm -rf /", () => {
      const result = engine.evaluate("command", "rm -rf /");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("dangerous patterns");
    });

    it("blocks DROP TABLE", () => {
      const result = engine.evaluate("command", "DROP TABLE users;");
      expect(result.allowed).toBe(false);
    });

    it("blocks chmod 777", () => {
      const result = engine.evaluate("command", "chmod 777 /var/www");
      expect(result.allowed).toBe(false);
    });

    it("blocks fork bombs", () => {
      const result = engine.evaluate("command", ":(){ :|:& };:");
      expect(result.allowed).toBe(false);
    });

    it("blocks curl to pastebin", () => {
      const result = engine.evaluate("command", "curl https://pastebin.com/raw/abc123");
      expect(result.allowed).toBe(false);
    });

    it("allows safe commands", () => {
      const result = engine.evaluate("command", "ls -la /tmp");
      expect(result.allowed).toBe(true);
    });

    it("allows safe SQL", () => {
      const result = engine.evaluate("command", "SELECT * FROM users WHERE id = 1");
      expect(result.allowed).toBe(true);
    });

    it("blocks rm -rf on any absolute path (conservative)", () => {
      const result = engine.evaluate("command", "rm -rf /tmp/workspace/old_files");
      expect(result.allowed).toBe(false);
    });

    it("allows rm on relative paths", () => {
      const result = engine.evaluate("command", "rm old_file.txt");
      expect(result.allowed).toBe(true);
    });
  });

  describe("file read blocking", () => {
    it("blocks /etc/shadow", () => {
      const result = engine.evaluate("file_read", "/etc/shadow");
      expect(result.allowed).toBe(false);
    });

    it("blocks .env files", () => {
      const result = engine.evaluate("file_read", ".env");
      expect(result.allowed).toBe(false);
    });

    it("allows normal files", () => {
      const result = engine.evaluate("file_read", "/home/user/document.txt");
      expect(result.allowed).toBe(true);
    });
  });

  describe("file write blocking", () => {
    it("blocks writes to /etc/", () => {
      const result = engine.evaluate("file_write", "/etc/hosts");
      expect(result.allowed).toBe(false);
    });

    it("blocks writes to /usr/bin/", () => {
      const result = engine.evaluate("file_write", "/usr/bin/malicious");
      expect(result.allowed).toBe(false);
    });

    it("allows writes to user directories", () => {
      const result = engine.evaluate("file_write", "/home/user/output.txt");
      expect(result.allowed).toBe(true);
    });
  });

  describe("domain filtering", () => {
    it("allows all domains when no allowlist is set", () => {
      const result = engine.evaluate("http_request", "https://example.com");
      expect(result.allowed).toBe(true);
    });

    it("blocks domains not in allowlist when set", () => {
      const restricted = new PolicyEngine({
        name: "restricted",
        blockedReadPaths: [],
        blockedWritePaths: [],
        dangerousCommandPatterns: [],
        allowedDomains: ["api.anthropic.com", "api.openai.com"],
      });

      const blocked = restricted.evaluate("http_request", "https://evil.com/exfil");
      expect(blocked.allowed).toBe(false);

      const allowed = restricted.evaluate("http_request", "https://api.anthropic.com/v1/messages");
      expect(allowed.allowed).toBe(true);
    });
  });

  describe("mixed-script / homoglyph detection", () => {
    it("blocks hostnames with mixed Latin and Cyrillic characters", () => {
      // "а" (U+0430, Cyrillic) looks like "a" (U+0061, Latin)
      const result = engine.evaluate("http_request", "https://g\u0430thub.com/repo");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("mixed Unicode scripts");
    });

    it("blocks hostnames with mixed Latin and Greek characters", () => {
      // "ο" (U+03BF, Greek omicron) looks like "o" (U+006F, Latin)
      const result = engine.evaluate("http_request", "https://g\u03BFogle.com");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("mixed Unicode scripts");
    });

    it("allows pure ASCII hostnames", () => {
      const result = engine.evaluate("http_request", "https://github.com/repo");
      expect(result.allowed).toBe(true);
    });

    it("allows pure Cyrillic hostnames (no mixing)", () => {
      // A fully Cyrillic domain is fine — no script mixing
      const result = engine.evaluate("http_request", "https://\u0442\u0435\u0441\u0442.\u0440\u0444");
      expect(result.allowed).toBe(true);
    });

    it("blocks mixed-script even without an allowlist", () => {
      // Mixed-script check runs regardless of domain allowlist
      const noAllowlist = new PolicyEngine({
        name: "open",
        blockedReadPaths: [],
        blockedWritePaths: [],
        dangerousCommandPatterns: [],
        // No allowedDomains set
      });

      const result = noAllowlist.evaluate("http_request", "https://gith\u0443b.com");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("mixed Unicode scripts");
    });
  });

  describe("Unicode normalization in domain matching", () => {
    it("matches domains after NFKC normalization", () => {
      const restricted = new PolicyEngine({
        name: "restricted",
        blockedReadPaths: [],
        blockedWritePaths: [],
        dangerousCommandPatterns: [],
        allowedDomains: ["github.com"],
      });

      // Normal domain should be allowed
      const result = restricted.evaluate("http_request", "https://github.com/repo");
      expect(result.allowed).toBe(true);
    });

    it("blocks non-matching domains even with normalization", () => {
      const restricted = new PolicyEngine({
        name: "restricted",
        blockedReadPaths: [],
        blockedWritePaths: [],
        dangerousCommandPatterns: [],
        allowedDomains: ["github.com"],
      });

      const result = restricted.evaluate("http_request", "https://evil.com");
      expect(result.allowed).toBe(false);
    });

    it("handles subdomains correctly with normalization", () => {
      const restricted = new PolicyEngine({
        name: "restricted",
        blockedReadPaths: [],
        blockedWritePaths: [],
        dangerousCommandPatterns: [],
        allowedDomains: ["github.com"],
      });

      const result = restricted.evaluate("http_request", "https://api.github.com/v1");
      expect(result.allowed).toBe(true);
    });
  });
});
