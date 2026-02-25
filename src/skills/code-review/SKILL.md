---
name: Code Review
description: Analyze code for bugs, security issues, style violations, and best practices. Reviews diffs, files, or entire repositories.
---

## Code Review Skill

When the user asks you to review code, follow this process:

### Step 1: Gather the Code
- If a file path is given, use `file_read` to read it
- If reviewing a diff or recent changes, use `shell` to run `git diff` or `git log -p`
- If a Git repo URL is provided, use `git` to clone it first

### Step 2: Analysis
Review the code for:
- **Bugs**: Logic errors, off-by-one, null dereferences, race conditions
- **Security**: SQL injection, XSS, hardcoded secrets, insecure dependencies
- **Performance**: N+1 queries, unnecessary allocations, missing indexes
- **Style**: Naming conventions, code organization, DRY violations
- **Best practices**: Error handling, input validation, documentation

### Step 3: Report
Format your review as:
1. **Summary**: One paragraph overall assessment
2. **Critical Issues**: Bugs and security problems (must fix)
3. **Suggestions**: Improvements and best practices (should fix)
4. **Positive Notes**: Things done well

Reference specific line numbers and file paths. Suggest concrete fixes, not just problems.
