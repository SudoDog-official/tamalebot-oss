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
import { readFile, writeFile, mkdir, unlink, chmod } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import type { Tool } from "@anthropic-ai/sdk/resources/messages.js";
import type { PolicyEngine, PolicyDecision } from "../security/policy-engine.js";
import type { AuditTrail } from "../security/audit-trail.js";
import type { CredentialVault } from "../security/vault.js";
import type { StorageBackend } from "../storage/index.js";

export interface ToolResult {
  output: string;
  isError: boolean;
}

export interface ToolContext {
  policy: PolicyEngine;
  audit: AuditTrail;
  agentId: string;
  workDir: string;
  vault?: CredentialVault;
  storage?: StorageBackend;
  agentName?: string;
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
  {
    name: "vault",
    description:
      "Manage credentials in the secure vault. Store and retrieve API keys, SSH keys, " +
      "tokens, and other secrets. Credentials are encrypted at rest.",
    input_schema: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          enum: ["set", "get", "delete", "list", "generate_ssh_key"],
          description: "The vault action to perform",
        },
        name: {
          type: "string",
          description: "Credential name (uppercase, e.g. MY_API_KEY). Required for set/get/delete/generate_ssh_key",
        },
        value: {
          type: "string",
          description: "Credential value (required for set)",
        },
        type: {
          type: "string",
          enum: ["api_key", "ssh_key", "token", "database_url", "generic"],
          description: "Credential type (for set, default: generic)",
        },
        description: {
          type: "string",
          description: "Optional description of this credential",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "ssh_exec",
    description:
      "Execute a command on a remote host via SSH. Requires an SSH key stored in the vault. " +
      "Use vault generate_ssh_key first, then add the public key to the remote server.",
    input_schema: {
      type: "object" as const,
      properties: {
        host: {
          type: "string",
          description: "Remote hostname or IP address",
        },
        command: {
          type: "string",
          description: "The command to execute on the remote host",
        },
        user: {
          type: "string",
          description: "SSH user (default: root)",
        },
        port: {
          type: "number",
          description: "SSH port (default: 22)",
        },
        key_name: {
          type: "string",
          description: "Vault credential name for the SSH key (default: SSH_KEY)",
        },
        timeout_ms: {
          type: "number",
          description: "Timeout in milliseconds (default: 30000, max: 120000)",
        },
      },
      required: ["host", "command"],
    },
  },
  {
    name: "git",
    description:
      "Git operations. Clone repos, pull, commit, push, check status and diffs. " +
      "For private repos, store a deploy key in the vault first.",
    input_schema: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          enum: ["clone", "pull", "push", "status", "diff", "commit", "log", "checkout"],
          description: "The git action to perform",
        },
        repo: {
          type: "string",
          description: "Repository URL (required for clone)",
        },
        path: {
          type: "string",
          description: "Working directory (default: /tmp/workspace)",
        },
        message: {
          type: "string",
          description: "Commit message (for commit action)",
        },
        branch: {
          type: "string",
          description: "Branch name (for checkout action)",
        },
        key_name: {
          type: "string",
          description: "Vault credential name for deploy key (default: GIT_DEPLOY_KEY)",
        },
        args: {
          type: "string",
          description: "Additional git arguments",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "schedule",
    description:
      "Create, list, or manage scheduled tasks. Tasks run on a cron schedule and " +
      "execute a message/instruction to the agent when triggered.",
    input_schema: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          enum: ["create", "list", "delete", "pause", "resume"],
          description: "The schedule action to perform",
        },
        id: {
          type: "string",
          description: "Schedule ID (for delete/pause/resume)",
        },
        name: {
          type: "string",
          description: "Human-readable name (for create)",
        },
        cron: {
          type: "string",
          description: "Cron expression, e.g. '0 9 * * *' for daily at 9am (for create)",
        },
        task: {
          type: "string",
          description: "The instruction to send to the agent when triggered (for create)",
        },
      },
      required: ["action"],
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
    case "vault":
      return executeVault(input, ctx);
    case "ssh_exec":
      return executeSSHExec(input, ctx);
    case "git":
      return executeGit(input, ctx);
    case "schedule":
      return executeSchedule(input, ctx);
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

// --- Vault Tool ---

async function executeVault(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  if (!ctx.vault) {
    return { output: "Vault not available (no R2 storage configured)", isError: true };
  }

  const action = String(input.action ?? "");
  const name = String(input.name ?? "");

  // Policy check
  const decision = ctx.policy.evaluate("vault", `${action} ${name}`);
  ctx.audit.log(ctx.agentId, "vault", `${action} ${name}`, decision.allowed ? "allowed" : "blocked", decision.reason);
  if (!decision.allowed) {
    return { output: `BLOCKED by security policy: ${decision.reason}`, isError: true };
  }

  try {
    switch (action) {
      case "set": {
        const value = String(input.value ?? "");
        const type = (String(input.type ?? "generic")) as import("../security/vault.js").CredentialType;
        const description = input.description ? String(input.description) : undefined;
        if (!name) return { output: "Missing 'name' parameter", isError: true };
        if (!value) return { output: "Missing 'value' parameter", isError: true };
        await ctx.vault.set(name, value, { type, description });
        return { output: `Credential '${name}' stored (type: ${type})`, isError: false };
      }
      case "get": {
        if (!name) return { output: "Missing 'name' parameter", isError: true };
        const cred = await ctx.vault.get(name);
        if (!cred) return { output: `Credential '${name}' not found`, isError: true };
        // Mask the value — show first 4 chars only
        const masked = cred.value.length > 8
          ? cred.value.slice(0, 4) + "*".repeat(Math.min(cred.value.length - 4, 20))
          : "****";
        return {
          output: `Credential '${name}' (type: ${cred.meta.type}): ${masked}\nCreated: ${cred.meta.createdAt}${cred.meta.description ? `\nDescription: ${cred.meta.description}` : ""}`,
          isError: false,
        };
      }
      case "delete": {
        if (!name) return { output: "Missing 'name' parameter", isError: true };
        await ctx.vault.delete(name);
        return { output: `Credential '${name}' deleted`, isError: false };
      }
      case "list": {
        const creds = await ctx.vault.list();
        if (creds.length === 0) return { output: "Vault is empty", isError: false };
        const lines = creds.map(c =>
          `  ${c.name} (${c.type}) — ${c.description || "no description"} [${c.createdAt}]`
        );
        return { output: `Credentials (${creds.length}):\n${lines.join("\n")}`, isError: false };
      }
      case "generate_ssh_key": {
        if (!name) return { output: "Missing 'name' parameter for SSH key", isError: true };
        const pubKey = await ctx.vault.generateSSHKey(name);
        return {
          output: `SSH key pair generated and stored.\nPrivate key: ${name} (in vault)\nPublic key: ${name}_PUB (in vault)\n\nPublic key (add to authorized_keys):\n${pubKey}`,
          isError: false,
        };
      }
      default:
        return { output: `Unknown vault action: ${action}`, isError: true };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { output: `Vault error: ${msg}`, isError: true };
  }
}

// --- SSH Exec Tool ---

async function executeSSHExec(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  if (!ctx.vault) {
    return { output: "SSH requires the credential vault (no R2 storage configured)", isError: true };
  }

  const host = String(input.host ?? "");
  const command = String(input.command ?? "");
  const user = String(input.user ?? "root");
  const port = Number(input.port) || 22;
  const keyName = String(input.key_name ?? "SSH_KEY");
  const timeoutMs = Math.min(Number(input.timeout_ms) || 30000, 120000);

  if (!host) return { output: "Missing 'host' parameter", isError: true };
  if (!command) return { output: "Missing 'command' parameter", isError: true };

  const target = `${user}@${host}:${port}`;

  // Policy check
  const decision = ctx.policy.evaluate("ssh_exec", target);
  ctx.audit.log(ctx.agentId, "ssh_exec", `${target} — ${command.slice(0, 100)}`, decision.allowed ? "allowed" : "blocked", decision.reason);
  if (!decision.allowed) {
    return { output: `BLOCKED by security policy: ${decision.reason}`, isError: true };
  }

  // Get SSH key from vault
  const privateKey = await ctx.vault.getSSHKey(keyName);
  if (!privateKey) {
    return {
      output: `SSH key '${keyName}' not found in vault. Generate one with: vault generate_ssh_key ${keyName}`,
      isError: true,
    };
  }

  // Write temp key file
  const tmpKeyPath = `/tmp/.ssh_key_${randomUUID().slice(0, 8)}`;
  try {
    await writeFile(tmpKeyPath, privateKey, { mode: 0o600 });

    return await new Promise<ToolResult>((resolve) => {
      exec(
        `ssh -i ${tmpKeyPath} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p ${port} ${user}@${host} ${JSON.stringify(command)}`,
        {
          timeout: timeoutMs,
          maxBuffer: 1024 * 1024,
          env: { ...process.env, TAMALEBOT_AGENT_ID: ctx.agentId },
        },
        (error, stdout, stderr) => {
          if (error) {
            const output = stderr || error.message;
            resolve({
              output: `SSH command failed (exit ${error.code ?? "unknown"}):\n${output}`.slice(0, 10000),
              isError: true,
            });
          } else {
            const output = stdout + (stderr ? `\nstderr: ${stderr}` : "");
            resolve({ output: output.slice(0, 10000), isError: false });
          }
        },
      );
    });
  } finally {
    try { await unlink(tmpKeyPath); } catch { /* already gone */ }
  }
}

// --- Git Tool ---

async function executeGit(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  const action = String(input.action ?? "");
  const repo = String(input.repo ?? "");
  const path = String(input.path ?? ctx.workDir);
  const message = String(input.message ?? "");
  const branch = String(input.branch ?? "");
  const keyName = String(input.key_name ?? "GIT_DEPLOY_KEY");
  const args = String(input.args ?? "");

  const target = `${action} ${repo || path}`;

  // Policy check
  const decision = ctx.policy.evaluate("git", target);
  ctx.audit.log(ctx.agentId, "git", target, decision.allowed ? "allowed" : "blocked", decision.reason);
  if (!decision.allowed) {
    return { output: `BLOCKED by security policy: ${decision.reason}`, isError: true };
  }

  // For auth-requiring operations, set up SSH key
  let tmpKeyPath: string | null = null;
  let sshCommand = "";
  const needsAuth = ["clone", "push", "pull"].includes(action) && ctx.vault;

  if (needsAuth) {
    const privateKey = await ctx.vault!.getSSHKey(keyName);
    if (privateKey) {
      tmpKeyPath = `/tmp/.git_key_${randomUUID().slice(0, 8)}`;
      await writeFile(tmpKeyPath, privateKey, { mode: 0o600 });
      sshCommand = `GIT_SSH_COMMAND='ssh -i ${tmpKeyPath} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null'`;
    }
  }

  try {
    let cmd: string;
    switch (action) {
      case "clone":
        if (!repo) return { output: "Missing 'repo' parameter for clone", isError: true };
        cmd = `${sshCommand} git clone ${args} ${JSON.stringify(repo)} ${JSON.stringify(path)}`;
        break;
      case "pull":
        cmd = `cd ${JSON.stringify(path)} && ${sshCommand} git pull ${args}`;
        break;
      case "push":
        cmd = `cd ${JSON.stringify(path)} && ${sshCommand} git push ${args}`;
        break;
      case "status":
        cmd = `cd ${JSON.stringify(path)} && git status ${args}`;
        break;
      case "diff":
        cmd = `cd ${JSON.stringify(path)} && git diff ${args}`;
        break;
      case "commit":
        if (!message) return { output: "Missing 'message' parameter for commit", isError: true };
        cmd = `cd ${JSON.stringify(path)} && git add -A && git commit -m ${JSON.stringify(message)} ${args}`;
        break;
      case "log":
        cmd = `cd ${JSON.stringify(path)} && git log --oneline -20 ${args}`;
        break;
      case "checkout":
        if (!branch) return { output: "Missing 'branch' parameter for checkout", isError: true };
        cmd = `cd ${JSON.stringify(path)} && git checkout ${JSON.stringify(branch)} ${args}`;
        break;
      default:
        return { output: `Unknown git action: ${action}`, isError: true };
    }

    return await new Promise<ToolResult>((resolve) => {
      exec(
        cmd,
        {
          cwd: ctx.workDir,
          timeout: 60000,
          maxBuffer: 1024 * 1024,
          env: { ...process.env, TAMALEBOT_AGENT_ID: ctx.agentId },
        },
        (error, stdout, stderr) => {
          if (error) {
            const output = stderr || error.message;
            resolve({
              output: `git ${action} failed (exit ${error.code ?? "unknown"}):\n${output}`.slice(0, 10000),
              isError: true,
            });
          } else {
            const output = stdout + (stderr ? `\nstderr: ${stderr}` : "");
            resolve({ output: output.slice(0, 10000), isError: false });
          }
        },
      );
    });
  } finally {
    if (tmpKeyPath) {
      try { await unlink(tmpKeyPath); } catch { /* already gone */ }
    }
  }
}

// --- Schedule Tool ---

interface ScheduleEntry {
  id: string;
  name: string;
  cron: string;
  task: string;
  agentName: string;
  enabled: boolean;
  createdAt: string;
  lastRun: string | null;
  lastResult: string | null;
}

function validateCron(expr: string): boolean {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  // Basic validation: each part is *, a number, or a range/step
  const patterns = [
    /^(\*|[0-9]{1,2})(\/[0-9]{1,2})?(-[0-9]{1,2})?(,[0-9]{1,2})*$/, // min
    /^(\*|[0-9]{1,2})(\/[0-9]{1,2})?(-[0-9]{1,2})?(,[0-9]{1,2})*$/, // hour
    /^(\*|[0-9]{1,2})(\/[0-9]{1,2})?(-[0-9]{1,2})?(,[0-9]{1,2})*$/, // day
    /^(\*|[0-9]{1,2})(\/[0-9]{1,2})?(-[0-9]{1,2})?(,[0-9]{1,2})*$/, // month
    /^(\*|[0-7])(\/[0-7])?(-[0-7])?(,[0-7])*$/,                      // dow
  ];
  return parts.every((p, i) => patterns[i].test(p));
}

async function executeSchedule(
  input: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult> {
  if (!ctx.storage) {
    return { output: "Schedules require R2 storage (not configured)", isError: true };
  }

  const action = String(input.action ?? "");

  // Policy check
  const decision = ctx.policy.evaluate("schedule", action);
  ctx.audit.log(ctx.agentId, "schedule", action, decision.allowed ? "allowed" : "blocked", decision.reason);
  if (!decision.allowed) {
    return { output: `BLOCKED by security policy: ${decision.reason}`, isError: true };
  }

  try {
    switch (action) {
      case "create": {
        const name = String(input.name ?? "");
        const cron = String(input.cron ?? "");
        const task = String(input.task ?? "");
        if (!name) return { output: "Missing 'name' for schedule", isError: true };
        if (!cron) return { output: "Missing 'cron' expression", isError: true };
        if (!task) return { output: "Missing 'task' instruction", isError: true };
        if (!validateCron(cron)) return { output: `Invalid cron expression: ${cron}. Use 5-field format: min hour day month dow`, isError: true };

        const id = randomUUID().slice(0, 8);
        const entry: ScheduleEntry = {
          id,
          name,
          cron,
          task,
          agentName: ctx.agentName ?? ctx.agentId,
          enabled: true,
          createdAt: new Date().toISOString(),
          lastRun: null,
          lastResult: null,
        };
        await ctx.storage.put(`schedules/${id}.json`, JSON.stringify(entry));
        return { output: `Schedule created: "${name}" (${cron})\nID: ${id}\nTask: ${task}`, isError: false };
      }
      case "list": {
        const keys = await ctx.storage.list("schedules/");
        if (keys.length === 0) return { output: "No schedules configured", isError: false };

        const schedules: ScheduleEntry[] = [];
        for (const key of keys) {
          try {
            const fullKey = key.endsWith(".json") ? key : `schedules/${key}`;
            const data = await ctx.storage.get(fullKey);
            if (data) schedules.push(JSON.parse(data.toString("utf-8")) as ScheduleEntry);
          } catch { /* skip corrupt */ }
        }

        const lines = schedules.map(s =>
          `  ${s.id} | ${s.name} | ${s.cron} | ${s.enabled ? "active" : "paused"} | last: ${s.lastRun ?? "never"} | ${s.lastResult ?? "—"}`
        );
        return { output: `Schedules (${schedules.length}):\n${lines.join("\n")}`, isError: false };
      }
      case "delete": {
        const id = String(input.id ?? "");
        if (!id) return { output: "Missing 'id' parameter", isError: true };
        await ctx.storage.delete(`schedules/${id}.json`);
        return { output: `Schedule ${id} deleted`, isError: false };
      }
      case "pause":
      case "resume": {
        const id = String(input.id ?? "");
        if (!id) return { output: "Missing 'id' parameter", isError: true };
        const data = await ctx.storage.get(`schedules/${id}.json`);
        if (!data) return { output: `Schedule ${id} not found`, isError: true };
        const entry = JSON.parse(data.toString("utf-8")) as ScheduleEntry;
        entry.enabled = action === "resume";
        await ctx.storage.put(`schedules/${id}.json`, JSON.stringify(entry));
        return { output: `Schedule ${id} ${action === "pause" ? "paused" : "resumed"}`, isError: false };
      }
      default:
        return { output: `Unknown schedule action: ${action}`, isError: true };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { output: `Schedule error: ${msg}`, isError: true };
  }
}
