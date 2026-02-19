// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { executeTool, TOOL_SCHEMAS, type ToolContext } from "../../src/agent/tools.js";
import { PolicyEngine } from "../../src/security/policy-engine.js";
import { AuditTrail } from "../../src/security/audit-trail.js";

describe("Tool Schemas", () => {
  it("should define all Phase 1 tools", () => {
    const names = TOOL_SCHEMAS.map((t) => t.name);
    expect(names).toContain("shell");
    expect(names).toContain("file_read");
    expect(names).toContain("file_write");
    expect(names).toContain("web_browse");
  });

  it("should have valid schemas with required fields", () => {
    for (const tool of TOOL_SCHEMAS) {
      expect(tool.name).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(tool.input_schema).toBeTruthy();
      expect(tool.input_schema.type).toBe("object");
    }
  });
});

describe("Tool Execution", () => {
  let ctx: ToolContext;
  let testDir: string;

  beforeEach(async () => {
    testDir = join(tmpdir(), `tamalebot-test-${Date.now()}`);
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

  describe("shell tool", () => {
    it("should execute a simple command", async () => {
      const result = await executeTool("shell", { command: "echo hello" }, ctx);
      expect(result.isError).toBe(false);
      expect(result.output.trim()).toBe("hello");
    });

    it("should block dangerous commands", async () => {
      const result = await executeTool(
        "shell",
        { command: "rm -rf /" },
        ctx
      );
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });

    it("should handle command failures", async () => {
      const result = await executeTool(
        "shell",
        { command: "exit 1" },
        ctx
      );
      expect(result.isError).toBe(true);
    });

    it("should respect timeout", async () => {
      const result = await executeTool(
        "shell",
        { command: "sleep 10", timeout_ms: 500 },
        ctx
      );
      expect(result.isError).toBe(true);
    });
  });

  describe("file_read tool", () => {
    it("should read a file", async () => {
      const filePath = join(testDir, "test.txt");
      await writeFile(filePath, "hello world");

      const result = await executeTool("file_read", { path: filePath }, ctx);
      expect(result.isError).toBe(false);
      expect(result.output).toBe("hello world");
    });

    it("should handle missing files", async () => {
      const result = await executeTool(
        "file_read",
        { path: join(testDir, "nonexistent.txt") },
        ctx
      );
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Failed to read");
    });

    it("should block sensitive file reads", async () => {
      const result = await executeTool(
        "file_read",
        { path: "/etc/shadow" },
        ctx
      );
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });
  });

  describe("file_write tool", () => {
    it("should write a file", async () => {
      const filePath = join(testDir, "output.txt");
      const result = await executeTool(
        "file_write",
        { path: filePath, content: "test content" },
        ctx
      );
      expect(result.isError).toBe(false);
      expect(result.output).toContain("File written");

      const content = await readFile(filePath, "utf-8");
      expect(content).toBe("test content");
    });

    it("should create parent directories", async () => {
      const filePath = join(testDir, "nested", "deep", "file.txt");
      const result = await executeTool(
        "file_write",
        { path: filePath, content: "nested content" },
        ctx
      );
      expect(result.isError).toBe(false);

      const content = await readFile(filePath, "utf-8");
      expect(content).toBe("nested content");
    });

    it("should block system directory writes", async () => {
      const result = await executeTool(
        "file_write",
        { path: "/etc/evil.conf", content: "bad" },
        ctx
      );
      expect(result.isError).toBe(true);
      expect(result.output).toContain("BLOCKED");
    });
  });

  describe("unknown tool", () => {
    it("should return error for unknown tools", async () => {
      const result = await executeTool("nonexistent", {}, ctx);
      expect(result.isError).toBe(true);
      expect(result.output).toContain("Unknown tool");
    });
  });
});
