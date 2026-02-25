# TamaleBot

Open-source AI agent runtime. Every tool call checked. Every action logged. Every agent isolated.

Deploy autonomous AI agents that can run shell commands, read/write files, browse the web, and connect to Telegram, Discord, WhatsApp, Slack, and email — all with security policy enforcement, audit trails, and encrypted credential storage.

## Quickstart

```bash
git clone https://github.com/SudoDog-official/tamalebot-oss.git
cd tamalebot-oss
npm install
npm run build

# Run interactively
TAMALEBOT_API_KEY=sk-ant-... npx tamalebot agent

# Or via Docker
docker compose -f docker/docker-compose.yml up
```

Set `TAMALEBOT_PROVIDER` to `anthropic`, `openai`, `moonshot`, `google`, or `minimax` and provide the matching API key. Defaults to Anthropic Claude.

## What's Included

| Component | Description |
|-----------|-------------|
| **Agent Runtime** | Think/act loop: LLM reasons, calls tools, gets results, repeats |
| **Security Engine** | Policy enforcement on every tool call — blocks destructive commands, sensitive file access, data exfiltration |
| **Audit Trail** | Append-only, signed log of every action and decision |
| **Credential Vault** | AES-256-GCM encrypted per-agent storage for API keys, SSH keys, tokens |
| **5 Integrations** | Telegram, Discord, WhatsApp, Slack, Email (IMAP/SMTP) |
| **4 Core Tools** | Shell commands, file read/write, web browsing |
| **Model Router** | Routes simple queries to cheap models, complex tasks to capable models — saves 40-70% on API costs |
| **Agent Skills** | Modular skill system via SKILL.md files |
| **CLI** | `tamalebot agent`, `tamalebot run`, `tamalebot init` |
| **Docker** | Hardened container: non-root, no privileges, read-only filesystem |

## Architecture

```
User Message
     |
     v
+--------------------+     +------------------+
| Agent Runtime      |---->| LLM Provider     |
| (think/act loop)   |<----| (Claude, GPT,    |
|                    |     |  Gemini, etc.)    |
| 1. Send to LLM    |     +------------------+
| 2. LLM picks tool |
| 3. Policy check   |---->+------------------+
| 4. Execute tool    |     | Security Engine  |
| 5. Return result   |     | - Policy check   |
| 6. Repeat          |     | - Audit log      |
+--------------------+     | - Credential mgr |
     |                     +------------------+
     v
+--------------------+
| Integrations       |
| Telegram, Discord, |
| WhatsApp, Slack,   |
| Email              |
+--------------------+
```

## Security

Every tool call passes through the policy engine before execution:

**Blocked by default:**
- Destructive commands: `rm -rf /`, `DROP TABLE`, `chmod 777`, fork bombs
- Sensitive file reads: `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`
- System directory writes: `/etc/`, `/usr/bin/`, `/boot/`
- Data exfiltration: `curl pastebin`, `wget ngrok`, `nc` to external IPs
- Encoding obfuscation: `base64 -d | sh`, hex decode pipelines

**5 Hardening Layers** (all enabled by default):

| Layer | What It Does |
|-------|-------------|
| Sandbox Web Browsing | Strips scripts, detects encoded payloads in web content |
| Block Data Exfiltration | Blocks shell commands sending workspace data externally |
| Default-Deny Outbound | Only allows HTTP to approved domain list |
| System Prompt Protection | Injects anti-injection instructions |
| Vault Access Protection | Blocks credential retrieval after browsing untrusted content |

## Integrations

Each integration connects to a messaging platform and forwards messages through the agent loop:

```bash
# Telegram
TELEGRAM_BOT_TOKEN=... npx tamalebot agent

# Discord
DISCORD_BOT_TOKEN=... npx tamalebot agent

# Slack (Socket Mode — no public URL needed)
SLACK_BOT_TOKEN=... SLACK_APP_TOKEN=... npx tamalebot agent

# Email (IMAP IDLE + SMTP)
EMAIL_IMAP_HOST=... EMAIL_IMAP_USER=... EMAIL_IMAP_PASS=... npx tamalebot agent
```

WhatsApp requires a publicly accessible webhook URL — see `src/integrations/whatsapp.ts` for setup.

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TAMALEBOT_API_KEY` | LLM provider API key | (required) |
| `TAMALEBOT_PROVIDER` | `anthropic`, `openai`, `moonshot`, `google`, `minimax` | `anthropic` |
| `TAMALEBOT_MODEL` | Model name | Provider default |
| `TAMALEBOT_POLICY` | Security policy name | `default` |
| `TAMALEBOT_SYSTEM_PROMPT` | Custom system prompt | (none) |
| `TAMALEBOT_MODE` | `repl` or `http` | `repl` |
| `TAMALEBOT_ROUTER_MODEL` | Cheap model for routing (enables cost optimization) | (disabled) |
| `TAMALEBOT_STORAGE_PATH` | Local persistent storage path | `/tmp/workspace/.tamalebot-data` |

See `.env.example` for the full list including integration tokens.

## Project Structure

```
src/
  agent/
    agent-loop.ts         # Core think/act cycle
    llm-client.ts         # Multi-provider LLM client
    tools.ts              # Tool schemas + executors (shell, file, web)
    model-router.ts       # Cost-optimization routing
    context-compressor.ts # Token-saving history compression
    skill-loader.ts       # Agent Skills discovery
    index.ts              # HTTP server + REPL runtime
  security/
    policy-engine.ts      # YAML-based policy enforcement
    audit-trail.ts        # Append-only signed logging
    vault.ts              # AES-256-GCM credential storage
    secret-manager.ts     # Credential injection + masking
  integrations/
    telegram.ts           # Telegram Bot API (long polling)
    discord.ts            # Discord WebSocket (discord.js)
    whatsapp.ts           # WhatsApp Cloud API (webhooks)
    slack.ts              # Slack Socket Mode (@slack/bolt)
    email.ts              # IMAP IDLE + SMTP
  storage/
    index.ts              # Storage interface + local filesystem backend
  cli/
    index.ts              # CLI entry point
    commands/             # agent, run, init, status
  skills/                 # Built-in agent skills (SKILL.md format)
config/
  default-policy.yaml     # Default security policy
docker/
  Dockerfile              # Hardened production container
  docker-compose.yml      # Local development setup
tests/                    # Full test suite
```

## Development

```bash
npm install
npm test          # Run all tests
npm run build     # Compile TypeScript
npm run dev       # Run in development mode
```

Requires Node.js >= 22.

## Cloud Hosting

Don't want to self-host? [tamalebot.com](https://tamalebot.com) runs your agents on Cloudflare's global network with a dashboard, one-click deploy, scheduled tasks, and MCP integration — $5/mo base.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
