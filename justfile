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

test-db:
    #!/usr/bin/env bash
    set -euo pipefail
    postgres_container="reauth-test-postgres-$$"
    mysql_container="reauth-test-mysql-$$"
    trap 'docker rm --force --volumes "$postgres_container" "$mysql_container" >/dev/null 2>&1 || true' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    docker run --detach --rm --name "$postgres_container" \
        --env POSTGRES_PASSWORD=reauth --env POSTGRES_DB=reauth \
        --publish 127.0.0.1::5432 postgres:18 >/dev/null
    docker run --detach --rm --name "$mysql_container" \
        --env MYSQL_ROOT_PASSWORD=reauth --env MYSQL_DATABASE=reauth \
        --publish 127.0.0.1::3306 mysql:8.4 >/dev/null

    postgres_address=$(docker port "$postgres_container" 5432/tcp)
    mysql_address=$(docker port "$mysql_container" 3306/tcp)
    export REAUTH_TEST_DATABASE=postgresql,mysql,sqlite
    export REAUTH_TEST_POSTGRESQL_URL="postgresql+asyncpg://postgres:reauth@$postgres_address/reauth"
    export REAUTH_TEST_MYSQL_URL="mysql+asyncmy://root:reauth@$mysql_address/reauth"

    for attempt in {1..60}; do
        if docker exec "$postgres_container" pg_isready --host=127.0.0.1 --username=postgres --dbname=reauth >/dev/null 2>&1 \
            && docker exec "$mysql_container" mysql --host=127.0.0.1 --user=root --password=reauth --database=reauth --execute='SELECT 1' >/dev/null 2>&1; then
            just test
            exit 0
        fi
        sleep 1
    done

    echo "Test databases did not become ready within 60 attempts" >&2
    docker logs "$postgres_container" >&2
    docker logs "$mysql_container" >&2
    exit 1

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
