# https://just.systems

install:
    uv sync --all-extras && pre-commit

lint:
    uv run ruff format .
    uv run ruff check --fix .
    uv run ty check reauth/ tests/

lint-check:
    uv run ruff format --check .
    uv run ruff check .
    uv run ty check reauth/ tests/

test:
    uv run pytest

test-cov-xml:
    uv run pytest --cov-report=xml

docs-serve:
    uv run zensical serve

docs-build:
    uv run zensical build --strict

build:
    uv sync --locked --all-extras --dev
    uv build --no-build-isolation

version bump:
    uvx hatch version {{bump}}
