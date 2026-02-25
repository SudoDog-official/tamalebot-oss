# TamaleBot Security Engine

Open-source security engine for [TamaleBot](https://tamalebot.com) AI agents. Policy enforcement, audit trails, and encrypted credential vault.

## What This Is

This repo contains TamaleBot's **security-critical code** — the parts you need to audit and trust. Every component that gates agent actions, logs decisions, or handles credentials is here under Apache 2.0.

- **Policy engine** — intercepts every tool call before execution. Blocks destructive commands, sensitive file access, data exfiltration, and encoding obfuscation attacks.
- **Audit trail** — append-only, cryptographically signed log of every action and decision.
- **Credential vault** — AES-256-GCM encrypted per-agent storage for API keys, SSH keys, and tokens.
- **Secret manager** — injects credentials at runtime, masks them from logs. Never written to disk.

The agent runtime, integrations, and orchestration layer are distributed as a Docker image and managed via [tamalebot.com](https://tamalebot.com). This repo is what lets you verify the security claims yourself.

## Why Open Source

This code gates your agent's commands, handles your API keys, and logs your actions. If you can't read it, you can't trust it. A closed-source security tool is indistinguishable from malware.

**What's open (this repo):** Everything that enforces security policy, logs decisions, or touches credentials.

**What's not here:** Agent runtime, messaging integrations, CLI, MCP server, dashboard. These are distributed as a Docker image — you can self-host it anywhere, but the source is proprietary.

**No lock-in:** The Docker image runs on Cloudflare, AWS, or your own hardware. The open security engine means you can verify exactly what's being enforced.

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
          | 4. Encoding check | --> Base64/hex obfuscation?
          | 5. Rate limit     | --> within budget?
          | 6. Log decision   | --> audit trail entry
          +-------------------+
                    |
                    v
            ALLOWED or BLOCKED
```

**Blocked by default:**
- Destructive commands: `rm -rf /`, `DROP TABLE`, `chmod 777`, fork bombs
- Sensitive file reads: `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`
- System directory writes: `/etc/`, `/usr/bin/`, `/boot/`
- Data exfiltration: `curl pastebin`, `wget ngrok`, `nc` to external IPs
- Encoding obfuscation: `base64 -d | sh`, hex decode pipelines, Unicode homoglyph domains

**5 Hardening Layers** (all enabled by default):

| Layer | What It Does |
|-------|-------------|
| Sandbox Web Browsing | Strips scripts, detects encoded payloads in web content |
| Block Data Exfiltration | Blocks shell commands sending workspace data externally |
| Default-Deny Outbound | Only allows HTTP to approved domain list |
| System Prompt Protection | Injects anti-injection instructions |
| Vault Access Protection | Blocks credential retrieval after browsing untrusted web content |

## Project Structure

```
src/
  security/
    policy-engine.ts    # Central policy: blocked patterns, allowlists, rate limits
    audit-trail.ts      # Append-only JSONL logging with signing
    vault.ts            # AES-256-GCM encrypted per-agent credential storage
    secret-manager.ts   # Credential injection and masking
    index.ts            # Exports
skills-spec/
  SKILL-FORMAT.md       # Agent Skills format specification (Anthropic open standard)
docker/
  Dockerfile            # Agent container image (hardened, non-root)
config/
  default-policy.yaml   # Default security policy
tests/
  security/             # Policy engine and secret manager tests
```

## Agent Skills Format

TamaleBot supports modular agent skills using `SKILL.md` files (Anthropic open standard). See [skills-spec/SKILL-FORMAT.md](./skills-spec/SKILL-FORMAT.md) for the format specification. Community-contributed skills are welcome.

## Docker

Each agent runs in a hardened container:

```bash
docker build -t tamalebot-agent -f docker/Dockerfile .
docker run --rm -it \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:size=100M \
  tamalebot-agent
```

Container hardening: non-root user, no privilege escalation, all capabilities dropped, read-only filesystem.

## Development

```bash
npm install
npm test          # Run security engine tests
npm run build     # Compile TypeScript
```

Requires Node.js >= 22.

## Using with TamaleBot

This security engine is built into every TamaleBot agent. To deploy agents:

1. **Cloud (managed):** [tamalebot.com](https://tamalebot.com) — deploy in 60 seconds, $5/mo base
2. **Self-hosted:** Pull the Docker image and run on your own infrastructure
3. **Claude integration:** Install [@tamalebot/mcp-server](https://www.npmjs.com/package/@tamalebot/mcp-server) to manage agents from Claude Desktop

## License

Apache 2.0 — see [LICENSE](./LICENSE).
