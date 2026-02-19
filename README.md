# TamaleBot

Security-first AI agent runtime. Every tool call checked. Every action logged. Every agent isolated.

## What This Is

TamaleBot is the open-source runtime that powers [tamalebot.com](https://tamalebot.com). This repo contains everything that touches your data:

- **Security policy engine** — intercepts every tool call before execution
- **Audit trail** — append-only, signed log of every action
- **Secret manager** — encrypted credential injection, never written to disk
- **Agent runtime** — hardened Docker container, one per agent
- **CLI tools** — `tamalebot run`, `tamalebot init`, `tamalebot status`
- **Token conservation** — request deduplication, context compression, budget guards
- **Integrations** — MCP-based connectors (Telegram, Slack, Email)

The closed-source parts (dashboard UI, orchestration, billing) never touch your data directly. They talk to this runtime via standard APIs.

## Quickstart

```bash
# Clone the repo
git clone https://github.com/SudoDog-official/tamalebot-oss.git
cd tamalebot-oss

# Install dependencies
npm install

# Build
npm run build

# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Start an interactive AI agent
tamalebot agent

# Or run a command with security policies applied
tamalebot run python my_agent.py
```

The interactive agent gives you a chat interface where the AI can browse the web, run shell commands, read/write files, and more — all policy-checked and audit-logged.

```bash
# Initialize a project config (optional)
tamalebot init

# Run as a Telegram bot
export TELEGRAM_BOT_TOKEN=...
tamalebot agent --telegram
```

## Security Engine

Every tool call passes through the policy engine before execution:

```
Agent wants to run: rm -rf /tmp/workspace
                    |
                    v
          +-------------------+
          | Policy Engine     |
          |                   |
          | 1. Check command  | --> dangerous pattern?
          | 2. Check paths    | --> sensitive file/directory?
          | 3. Check domain   | --> allowed outbound host?
          | 4. Log decision   | --> audit trail entry
          +-------------------+
                    |
                    v
            ALLOWED or BLOCKED
```

**Blocked by default:**
- Destructive commands: `rm -rf /`, `DROP TABLE`, `chmod 777`
- Sensitive file reads: `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`
- System directory writes: `/etc/`, `/usr/bin/`, `/boot/`
- Data exfiltration: `curl pastebin`, `wget ngrok`

**Configurable:** Edit `config/default-policy.yaml` or pass a custom policy.

## Project Structure

```
src/
  security/        # Policy engine, audit trail, secret manager
  agent/           # Agent runtime (runs inside Docker container)
  cli/             # CLI commands (init, run, status)
  integrations/    # MCP integration servers
  storage/         # S3-compatible storage abstraction
config/
  default-policy.yaml   # Default security policy
docker/
  Dockerfile            # Agent container image
  docker-compose.yml    # Local development
tests/
  security/        # Policy engine and secret manager tests
```

## Docker

Each agent runs in a hardened container:

```bash
# Build
docker build -t tamalebot-agent -f docker/Dockerfile .

# Run
docker run --rm -it \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:size=100M \
  tamalebot-agent
```

Container hardening:
- Non-root user
- No privilege escalation
- All capabilities dropped
- Read-only filesystem (except `/tmp`)
- No shared state between agents

## Development

```bash
# Install dependencies
npm install

# Run in dev mode
npm run dev

# Run tests
npm test

# Build
npm run build

# Lint
npm run lint
```

Requires Node.js >= 22.

## Why Open Source

This code intercepts your agent's commands, reads your API keys, and logs your actions. If you can't read it, you can't trust it. A closed-source security tool from an unknown company is indistinguishable from malware.

Everything that touches your data is here. Read it, audit it, fork it.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
