# https://just.systems

install:
    uv sync --locked --all-extras
    uv run --locked pre-commit install

lint:
    uv run --locked ruff format .
    uv run --locked ruff check --fix .
    uv run --locked ty check reauth/ tests/

lint-check:
    uv run --locked ruff format --check .
    uv run --locked ruff check .
    uv run --locked ty check reauth/ tests/

test:
    uv run --locked pytest

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
    uv run --locked pytest --cov-report=xml

ai-review base:
    cubic review --output-format stream-json -b {{quote(base)}}

docs-serve:
    uv run --locked zensical serve

docs-build:
    uv run --locked zensical build --strict

build:
    uv sync --locked --all-extras
    uv build --no-build-isolation

version bump:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain)" ]; then
        echo "Commit or stash changes before preparing a release." >&2
        exit 1
    fi
    uv sync --locked
    uv run --no-sync hatchling version {{quote(bump)}}
    release_version="$(uv run --no-sync hatchling version)"
    uv run --no-sync keepachangelog release "$release_version"
    test -n "$(uv run --no-sync keepachangelog show "$release_version")"
    uv lock
    git add reauth/__init__.py CHANGELOG.md uv.lock
    git commit -S -e -m "release: Bump version to $release_version"

release pr:
    #!/usr/bin/env bash
    set -euo pipefail
    pr={{quote(pr)}}
    if [[ ! "$pr" =~ ^[1-9][0-9]*$ ]]; then
        echo "Provide a pull request number." >&2
        exit 1
    fi
    release_commit="$(gh pr view --repo frankie567/reauth \
        --json state,baseRefName,mergeCommit,files \
        --jq 'select(.state == "MERGED" and .baseRefName == "main")
              | select(any(.files[]; .path == "reauth/__init__.py")
                       and any(.files[]; .path == "CHANGELOG.md"))
              | .mergeCommit.oid // empty' -- "$pr")"
    if [[ -z "$release_commit" ]]; then
        echo "Provide a merged release PR targeting main that updates the version and changelog." >&2
        exit 1
    fi
    git fetch --no-tags origin refs/heads/main
    if ! git merge-base --is-ancestor "$release_commit" FETCH_HEAD; then
        echo "The release commit must be on origin/main." >&2
        exit 1
    fi
    release_version="$(git show "$release_commit:reauth/__init__.py" | sed -n 's/^__version__ = "\([^"]*\)"$/\1/p')"
    if [[ ! "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([ab][0-9]+|rc[0-9]+)?$ ]]; then
        echo "The release commit must contain a valid release version." >&2
        exit 1
    fi
    release_notes="$(git show "$release_commit:CHANGELOG.md" | uv run --locked keepachangelog show "$release_version" /dev/stdin)"
    test -n "$release_notes"
    tag="v$release_version"
    git tag -s "$tag" "$release_commit" -m "Release $release_version"
    git push --no-follow-tags origin "refs/tags/$tag"

release-notes version:
    @uv run --locked keepachangelog show {{quote(version)}}

test-website:
    node --test tests/website/*.test.cjs
