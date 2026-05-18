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

## Data Persistence Pattern

When implementing abstract methods for data persistence (insert, update, delete), follow this consistent pattern:

**insert method:**

- Signature: `async def insert(self, model: ModelType) -> typing.Any`
- Receives the full data model containing data to persist
- Returns only the ID of the inserted record

**update method:**

- Signature: `async def update(self, model: ModelType) -> None`
- Receives the full data model containing data to persist
- Returns nothing

**delete method:**

- Signature: `async def delete(self, model: ModelType) -> None`
- Receives the full data model to delete
- Returns nothing

### Testing

- Leverage `dataclasses.asdict(model)` to easily dump dataclass instances for database operations

```python
# Example implementation
async def insert(self, enrollment: Enrollment) -> int:
    result = await self.connection.execute(
        insert(table).values(**dataclasses.asdict(enrollment)).returning(table.c.id)
    )
    return result.scalar_one()

async def update(self, enrollment: Enrollment) -> None:
    await self.connection.execute(
        update(table).where(table.c.id == enrollment.id).values(**dataclasses.asdict(enrollment))
    )

async def delete(self, enrollment: Enrollment) -> None:
    await self.connection.execute(
        delete(table).where(table.c.id == enrollment.id)
    )
```

## Conventions

- In the library code (not tests), use absolute imports within the `reauth` package (e.g., `from reauth.factors.base import FactorBase`).
- Use fully qualified imports for standard library (e.g., `import datetime`/`datetime.datetime.now`, `import abc`/`abc.ABC`).
- Use fully qualified import for typing (e.g., `import typing`/`typing.Any`).
- When you need an email address to add in tests, use `reauth@example.com`.

## Committing

**Never proactively commit without being asked to do so.**

If you are asked to commit, make sure to:

- Always check the unstaged changes before committing. Developers usually polish the code after the AI agent has done its part, and there might be some changes you need to be aware of.
- Always prefix your message with the area of the codebase you are modifying (close to the module hierarchy), followed by a colon and a brief description of the change. For example: `factors/totp: Add support for HMAC-SHA-256`, `authentication_session: Refactor session management logic`
