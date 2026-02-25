# TamaleBot Agent Skills Format

TamaleBot uses the Anthropic open standard for agent skills. Each skill is a `SKILL.md` file with YAML frontmatter and Markdown instructions.

## Format

```markdown
---
name: My Skill Name
description: A short description of what this skill does (used for discovery)
---

# Full Skill Instructions

Detailed instructions that get loaded into the agent's context when the skill
is activated. Write these as if you're instructing the LLM directly.

## Guidelines
- Be specific about input/output formats
- Include examples where helpful
- Keep total size under 2000 tokens for efficient context use
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable skill name |
| `description` | Yes | One-line description for progressive disclosure |

## Progressive Disclosure

Skills use a two-level loading strategy:
1. **Level 1 (always loaded)**: Only `name` and `description` (~100 tokens per skill)
2. **Level 2 (on-demand)**: Full SKILL.md content loaded when the agent decides a skill is relevant

This keeps the system prompt small while giving agents access to many skills.

## Example: Code Review Skill

```markdown
---
name: Code Review
description: Analyze code for bugs, security issues, and style violations
---

# Code Review

When asked to review code, follow this process:

1. Read the code carefully, understanding the overall structure
2. Check for security issues (injection, XSS, auth bypass)
3. Check for logic bugs (off-by-one, null handling, race conditions)
4. Check for style issues (naming, formatting, dead code)
5. Provide findings as a structured list with severity levels

## Severity Levels
- **Critical**: Security vulnerabilities, data loss risks
- **Warning**: Logic bugs, performance issues
- **Info**: Style suggestions, minor improvements
```

## Directory Structure

Place skills in the agent's skills directory (default: `/app/skills/`):

```
skills/
  code-review/
    SKILL.md
  web-research/
    SKILL.md
  writing-assistant/
    SKILL.md
```

Configure via environment variable:
- `TAMALEBOT_SKILLS_DIR` — path to skills directory
- `TAMALEBOT_ENABLED_SKILLS` — comma-separated list of skill IDs to enable
