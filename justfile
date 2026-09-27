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
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain)" ]; then
        echo "Commit or stash changes before preparing a release." >&2
        exit 1
    fi
    uv run --locked hatchling version {{quote(bump)}}
    release_version="$(uv run --no-sync hatchling version)"
    uv run --no-sync keepachangelog release "$release_version"
    test -n "$(uv run --no-sync keepachangelog show "$release_version")"
    uv lock
    git add reauth/__init__.py CHANGELOG.md uv.lock
    git commit -S -e -m "release: Bump version to $release_version"
    git tag -s "v$release_version" -m "Release $release_version"

release-notes version:
    @uv run --locked keepachangelog show {{quote(version)}}
