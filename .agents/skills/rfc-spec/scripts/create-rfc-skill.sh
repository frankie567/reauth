#!/bin/bash
set -euo pipefail

# RFC Skill Creator
# Creates an Agent Skill from an RFC URL following the Agent Skills specification
# Usage: ./create-rfc-skill.sh <rfc-url> [skills-base-dir]

if [ $# -lt 1 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <rfc-url> [skills-base-dir]"
    echo "Example: $0 https://www.rfc-editor.org/rfc/rfc8176.txt"
    echo "Example: $0 https://www.rfc-editor.org/rfc/rfc8176.txt /path/to/skills"
    exit 1
fi

RFC_URL="$1"
SKILLS_BASE="${2:-}"

# Extract RFC number from URL
RFC_NUMBER=$(basename "$RFC_URL" | sed 's/rfc\([0-9]*\).txt/\1/')

if [ -z "$RFC_NUMBER" ]; then
    echo "Error: Could not extract RFC number from URL: $RFC_URL"
    exit 1
fi

SKILL_NAME="rfc${RFC_NUMBER}"

# Validate skill name per Agent Skills spec
if ! [[ "$SKILL_NAME" =~ ^[a-z0-9-]+$ ]] || [[ "$SKILL_NAME" =~ ^- ]] || [[ "$SKILL_NAME" =~ -$ ]] || [[ "$SKILL_NAME" == *--* ]]; then
    echo "Error: Skill name '$SKILL_NAME' is invalid. Use lowercase letters, numbers, and hyphens only. Cannot start/end with hyphen or contain consecutive hyphens."
    exit 1
fi

# Determine skills directory
if [ -z "$SKILLS_BASE" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SKILLS_BASE="$(dirname "$(dirname "$SCRIPT_DIR")")"
fi

SKILLS_BASE="${SKILLS_BASE%/}/"
SKILL_DIR="${SKILLS_BASE}${SKILL_NAME}"

if [ -d "$SKILL_DIR" ]; then
    echo "Error: Skill directory already exists: $SKILL_DIR"
    exit 1
fi

mkdir -p "$SKILL_DIR/references"

echo "Downloading RFC $RFC_NUMBER..."
curl -sS -o "$SKILL_DIR/references/RFC${RFC_NUMBER}.txt" "$RFC_URL"

if [ ! -s "$SKILL_DIR/references/RFC${RFC_NUMBER}.txt" ]; then
    echo "Error: Failed to download RFC"
    rm -rf "$SKILL_DIR"
    exit 1
fi

# Create skeleton SKILL.md - LLM should enhance this based on RFC content
cat > "$SKILL_DIR/SKILL.md" <<EOF
---
name: $SKILL_NAME
description: "RFC $RFC_NUMBER. TODO: Add description based on RFC content. Use when working with this RFC."
---

# RFC $RFC_NUMBER

TODO: Add summary and key information from the RFC.

## When to Use This Skill

TODO: Specify use cases.

## Full RFC Text

See [references/RFC${RFC_NUMBER}.txt](references/RFC${RFC_NUMBER}.txt) for the complete document.
EOF

echo "Created skill skeleton: $SKILL_DIR"
echo "  - SKILL.md (edit based on RFC content)"
echo "  - references/RFC${RFC_NUMBER}.txt"
