#!/usr/bin/env bash
# Update this AntiFlag checkout from the branch that is currently checked out.
#
# Never switches branches. Fetches origin/<current branch> and fast-forwards to it.
# Stops without changes if the working tree is dirty (unless --allow-dirty),
# HEAD is detached, or local commits would be lost.
#
# Usage:
#   ./updaters.sh                 # update
#   ./updaters.sh --test          # also run the unit tests afterwards
#   ./updaters.sh --allow-dirty   # attempt the update with local changes
#
# Exit codes: 0 success or already up to date, 1 refused or failed, 2 usage error.

set -euo pipefail

REMOTE="origin"
ALLOW_DIRTY=0
RUN_TESTS=0

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "error: $*" >&2
    exit 1
}

for arg in "$@"; do
    case "$arg" in
        --allow-dirty) ALLOW_DIRTY=1 ;;
        --test) RUN_TESTS=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

cd "$(dirname "$0")"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git repository"

BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
[ -n "$BRANCH" ] || die "HEAD is detached; check out a branch before updating"

git remote get-url "$REMOTE" >/dev/null 2>&1 || die "no '$REMOTE' remote is configured"

if [ "$ALLOW_DIRTY" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
    die "uncommitted changes present; commit or stash them, or pass --allow-dirty"
fi

git fetch --quiet "$REMOTE" "$BRANCH" || die "could not fetch $REMOTE/$BRANCH; does it exist?"

LOCAL="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse FETCH_HEAD)"

if [ "$LOCAL" = "$REMOTE_HEAD" ]; then
    echo "$BRANCH is already up to date (${LOCAL:0:7})"
elif git merge-base --is-ancestor "$LOCAL" "$REMOTE_HEAD"; then
    git merge --ff-only FETCH_HEAD
    echo "updated $BRANCH: ${LOCAL:0:7} -> ${REMOTE_HEAD:0:7}"
elif git merge-base --is-ancestor "$REMOTE_HEAD" "$LOCAL"; then
    echo "$BRANCH is ahead of $REMOTE/$BRANCH; nothing to pull"
else
    die "$BRANCH has diverged from $REMOTE/$BRANCH; resolve it manually, nothing was changed"
fi

if [ "$RUN_TESTS" -eq 1 ]; then
    PY="$(command -v python3 || command -v python || true)"
    [ -n "$PY" ] || die "python3 not found; cannot run tests"
    echo "running tests..."
    "$PY" -m unittest discover -s tests
fi
