---
name: rfc-spec
description: Creates an Agent Skill from an RFC URL. Downloads the RFC text and creates a skeleton SKILL.md. The LLM should then read the RFC and enhance the skeleton with proper description, title, and key information. Use when you need to create a skill from an IETF RFC document.
---

# RFC Skill Creator

This skill provides a script to create a skeleton Agent Skill from an IETF RFC URL. The LLM must then read the downloaded RFC and enhance the generated SKILL.md.

## Usage

Run the script with an RFC URL:

```bash
scripts/create-rfc-skill.sh https://www.rfc-editor.org/rfc/rfc4226.txt
```

## What It Creates

```
rfc4226/
├── SKILL.md          # Skeleton - LLM must enhance this
└── references/
    └── RFCXXXX.txt    # Full RFC text for LLM to read
```

## LLM Workflow

1. Run the script to create the skeleton
2. Read the RFC from `references/RFCXXXX.txt`
3. Edit `SKILL.md` to:
    - Replace TODO placeholders with actual content
    - Add proper description (max 1024 chars)
    - **Quote the description in YAML frontmatter** if it contains colons or special characters to avoid parsing errors
    - Add relevant sections (Quick Reference, Key Concepts, etc.)
    - Ensure frontmatter follows Agent Skills spec

## Requirements

- `curl` for downloading RFC content
- `bash` for execution
- Write access to the target skills directory
