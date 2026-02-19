// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Agent Tools
 *
 * Defines the tools available to the agent. Each tool has:
 * - A schema (sent to the LLM so it knows how to call it)
 * - An executor (actually runs the action, after policy checks)
 *
 * Phase 1 tools: shell, file_read, file_write, web_browse
 */

import { exec } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { Tool } from "@anthropic-ai/sdk/resources/messages.js";
import type { PolicyEngine, PolicyDecision } from "../security/policy-engine.js";
import type { AuditTrail } from "../security/audit-trail.js";

export interface ToolResult {
  output: string;
  isError: boolean;
}

export interface ToolContext {
  policy: PolicyEngine;
  audit: AuditTrail;
  agentId: string;
  workDir: string;
}

/**
 * Tool definitions sent to the LLM.
 */
export const TOOL_SCHEMAS: Tool[] = [
  {
    name: "shell",
    description:
      "Execute a shell command. Use this for running scripts, installing packages, " +
      "checking system state, or any command-line operation. Commands run in a " +
      "sandboxed environment with security policy enforcement.",
    input_schema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "The shell command to execute",
        },
        timeout_ms: {
          type: "number",
          description: "Timeout in milliseconds (default: 30000, max: 120000)",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "file_read",
    description:
      "Read the contents of a file. Returns the file content as text. " +
      "Paths are relative to the agent workspace unless absolute.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Path to the file to read",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "file_write",
    description:
      "Write content to a file. Creates the file and parent directories if they " +
      "don't exist. Overwrites existing content.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Path to the file to write",
        },
        content: {
          type: "string",
          description: "Content to write to the file",
        },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "web_browse",
    description:
      "Fetch the text content of a web page. Returns the page text (HTML stripped). " +
      "Use this for reading documentation, checking APIs, or gathering information from the web.",
    input_schema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "The URL to fetch",
        },
      },
      required: ["url"],
    },
  },
];

/**
 * Execute a tool call after policy checks.
 */
export async function executeTool(
  toolName: string,
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  switch (toolName) {
    case "shell":
      return executeShell(input, ctx);
    case "file_read":
      return executeFileRead(input, ctx);
    case "file_write":
      return executeFileWrite(input, ctx);
    case "web_browse":
      return executeWebBrowse(input, ctx);
    default:
      return { output: `Unknown tool: ${toolName}`, isError: true };
  }
}

async function executeShell(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  const command = String(input.command ?? "");
  const timeoutMs = Math.min(Number(input.timeout_ms) || 30000, 120000);

  // Policy check
  const decision = ctx.policy.evaluate("command", command);
  ctx.audit.log(ctx.agentId, "command", command, decision.allowed ? "allowed" : "blocked", decision.reason);

  if (!decision.allowed) {
    return {
      output: `BLOCKED by security policy: ${decision.reason}`,
      isError: true,
    };
  }

  return new Promise((resolve) => {
    exec(
      command,
      {
        cwd: ctx.workDir,
        timeout: timeoutMs,
        maxBuffer: 1024 * 1024, // 1MB output limit
        env: { ...process.env, TAMALEBOT_AGENT_ID: ctx.agentId },
      },
      (error, stdout, stderr) => {
        if (error) {
          const output = stderr || error.message;
          resolve({
            output: `Command failed (exit ${error.code ?? "unknown"}):\n${output}`.slice(0, 10000),
            isError: true,
          });
        } else {
          const output = stdout + (stderr ? `\nstderr: ${stderr}` : "");
          resolve({ output: output.slice(0, 10000), isError: false });
        }
      }
    );
  });
}

async function executeFileRead(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  const path = String(input.path ?? "");

  // Policy check
  const decision = ctx.policy.evaluate("file_read", path);
  ctx.audit.log(ctx.agentId, "file_read", path, decision.allowed ? "allowed" : "blocked", decision.reason);

  if (!decision.allowed) {
    return {
      output: `BLOCKED by security policy: ${decision.reason}`,
      isError: true,
    };
  }

  try {
    const content = await readFile(path, "utf-8");
    return { output: content.slice(0, 50000), isError: false };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { output: `Failed to read file: ${msg}`, isError: true };
  }
}

async function executeFileWrite(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  const path = String(input.path ?? "");
  const content = String(input.content ?? "");

  // Policy check
  const decision = ctx.policy.evaluate("file_write", path);
  ctx.audit.log(ctx.agentId, "file_write", path, decision.allowed ? "allowed" : "blocked", decision.reason);

  if (!decision.allowed) {
    return {
      output: `BLOCKED by security policy: ${decision.reason}`,
      isError: true,
    };
  }

  try {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content, "utf-8");
    return { output: `File written: ${path} (${content.length} bytes)`, isError: false };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { output: `Failed to write file: ${msg}`, isError: true };
  }
}

async function executeWebBrowse(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  const url = String(input.url ?? "");

  // Policy check (domain allowlist)
  const decision = ctx.policy.evaluate("http_request", url);
  ctx.audit.log(ctx.agentId, "http_request", url, decision.allowed ? "allowed" : "blocked", decision.reason);

  if (!decision.allowed) {
    return {
      output: `BLOCKED by security policy: ${decision.reason}`,
      isError: true,
    };
  }

  try {
    const response = await fetch(url, {
      headers: {
        "User-Agent": "TamaleBot/0.1.0",
        Accept: "text/html,application/xhtml+xml,text/plain",
      },
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      return {
        output: `HTTP ${response.status}: ${response.statusText}`,
        isError: true,
      };
    }

    const html = await response.text();
    // Strip HTML tags for a rough text extraction
    const text = html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim();

    return { output: text.slice(0, 20000), isError: false };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { output: `Failed to fetch URL: ${msg}`, isError: true };
  }
}
