# Agent Instructions

This document provides essential guidance for AI agents contributing to Reauth. Imagine this file as a new joiner to the team who needs to understand the coding standards, practices, and conventions used in this repository.

## General Guidelines

- Do not add comments to the code unless necessary. The code should be self-explanatory.
- Use meaningful variable and function names.
- Follow good practices and code conventions.
- Make sure that all the new code is maintainable and follows the SOLID principles.
- Do not modify unrelated code to the task or issue you are working on.

### Linting and testing

The project needs to be linted and type-checked. To do so, run:

```bash
just lint
```

Tests are located in the `tests/` directory. It uses `pytest` for testing. To run the tests, use:

```bash
just test
```

Always privilege the `just` commands as described above to check your work. **Don't run manual linting or testing commands without being asked to do so.**

### Running Python commands

The project uses `uv` for environment and dependency management. To run Python commands, use:

```bash
uv run python <your_command_here>
```

## Logging

The library has a built-in OWASP-compliant logging infrastructure. Use it for security-relevant events.

**Infrastructure:**
`reauth/logging.py` with NullHandler (disabled by default, no warnings). Get logger via:

```python
from reauth.logging import get_logger
logger = get_logger(__name__)
```

**Levels:**

- DEBUG: method entry/attempt
- INFO: success events (session created, TOTP enabled)
- WARNING: auth failures (invalid code/token), validation errors (not enrolled/enabled)

**Add logging to:** authentication methods, session lifecycle, factor operations, authorization failures.

**NEVER log:** tokens, secrets, passwords, encryption keys, raw PII, database connection strings.

**PII handling:** Use `_hash_email(email)` (SHA-256) for correlation without exposing raw emails.

**Pattern:**

```python
logger.debug("Method called", extra={"safe": "data"})
try:
    # ... logic ...
    logger.info("Success", extra={"result": "data"})
except AuthException:
    logger.warning("Failed: reason", extra={"context": "data"})
    raise
```

**OWASP checklist:** auth successes/failures, session events, authorization failures, sensitive data excluded, PII handled, disabled by default.

## Committing

**Never proactively commit without being asked to do so.**

If you are asked to commit, make sure to:

- Always check the unstaged changes before committing. Developers usually polish the code after the AI agent has done its part, and there might be some changes you need to be aware of.
- Always prefix your message with the area of the codebase you are modifying (close to the module hierarchy), followed by a colon and a brief description of the change. For example: `factors/totp: Add support for HMAC-SHA-256`, `authentication_session: Refactor session management logic`
