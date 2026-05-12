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

### Running Python commands

The project uses `uv` for environment and dependency management. To run Python commands, use:

```bash
uv run python <your_command_here>
```

## Committing

When asked to commit on behalf of the team, please follow the following guidelines.

- Always check the unstaged changes before committing. Developers usually polish the code after the LLM has done its part, and there might be some changes you need to be aware of.
- Always prefix your message with the area of the codebase you are modifying (close to the module hierarchy), followed by a colon and a brief description of the change. For example: `factors/totp: Add support for HMAC-SHA-256`, `authentication_session: Refactor session management logic`
