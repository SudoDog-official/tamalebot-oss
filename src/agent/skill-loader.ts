// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Skill Loader
 *
 * Discovers and parses Agent Skills following the Anthropic Agent Skills
 * open standard. Each skill is a directory containing a SKILL.md file
 * with YAML frontmatter (name + description) and markdown instructions.
 *
 * Progressive disclosure:
 *   Level 1: name + description loaded at startup (~100 tokens per skill)
 *   Level 2: full SKILL.md read on-demand by the LLM via file_read
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

export interface SkillMetadata {
  name: string;
  description: string;
  /** Absolute path to the SKILL.md file */
  path: string;
  /** Directory name (used as skill ID) */
  id: string;
}

/**
 * Discover all skills in a directory.
 * Each subdirectory with a valid SKILL.md file is a skill.
 */
export async function discoverSkills(skillsDir: string): Promise<SkillMetadata[]> {
  const skills: SkillMetadata[] = [];

  let entries: string[];
  try {
    entries = await readdir(skillsDir);
  } catch {
    return skills;
  }

  for (const entry of entries) {
    const skillDir = join(skillsDir, entry);
    const skillFile = join(skillDir, "SKILL.md");

    try {
      const st = await stat(skillDir);
      if (!st.isDirectory()) continue;

      const content = await readFile(skillFile, "utf-8");
      const meta = parseFrontmatter(content);

      if (meta.name && meta.description) {
        skills.push({
          name: meta.name,
          description: meta.description,
          path: skillFile,
          id: entry,
        });
      }
    } catch {
      continue;
    }
  }

  return skills;
}

/**
 * Parse YAML frontmatter from a SKILL.md file.
 */
function parseFrontmatter(content: string): { name?: string; description?: string } {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};

  try {
    const parsed = parseYaml(match[1]) as Record<string, unknown>;
    return {
      name: typeof parsed.name === "string" ? parsed.name : undefined,
      description: typeof parsed.description === "string" ? parsed.description : undefined,
    };
  } catch {
    return {};
  }
}

/**
 * Build the Level 1 system prompt section for enabled skills.
 */
export function buildSkillsPromptSection(skills: SkillMetadata[]): string {
  if (skills.length === 0) return "";

  const lines = skills.map(
    (s) => `- **${s.name}** (${s.path}): ${s.description}`
  );

  return `

AVAILABLE SKILLS:
You have ${skills.length} specialized skills available. When a user's request matches a skill, use file_read to load the full instructions from the path shown, then follow those instructions to complete the task.

${lines.join("\n")}
`;
}
