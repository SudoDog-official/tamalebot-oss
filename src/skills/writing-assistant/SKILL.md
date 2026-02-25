---
name: Writing Assistant
description: Help draft, edit, and improve written content including emails, documentation, READMEs, blog posts, and technical writing.
---

## Writing Assistant Skill

When the user needs help with writing:

### Drafting
- Ask about audience, tone, and purpose if not specified
- Create a structured outline before writing
- Write in clear, concise prose appropriate to the format
- Use `file_write` to save drafts to the workspace

### Editing
- Use `file_read` to load existing content
- Check for: clarity, grammar, tone consistency, structure
- Suggest specific improvements with before/after examples
- Preserve the author's voice while improving readability

### Format-Specific Guidelines

**README**: Title, badges, description, install, usage, API, contributing, license
**Email**: Clear subject, concise body, specific call-to-action
**Blog Post**: Hook, structured sections, conclusion with takeaway
**Technical Docs**: Overview, prerequisites, step-by-step, troubleshooting
**API Docs**: Endpoint, method, parameters, request/response examples

### Process
1. Understand what is needed (draft vs. edit, format, audience)
2. If editing, read the existing content first
3. Produce the content (or suggested edits)
4. Save to workspace via `file_write`
5. Offer to iterate based on feedback
