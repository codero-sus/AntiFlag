#!/usr/bin/env python3
"""Update this AntiFlag checkout from the branch that is currently checked out.

The updater never switches branches. It fetches ``origin/<current branch>`` and
fast-forwards to it. It stops without changing anything if the working tree is
dirty (unless ``--allow-dirty``), HEAD is detached, or local commits would be
lost.

Usage:
    python3 updaters.py            # update, then report
    python3 updaters.py --test     # also run the unit tests afterwards
    python3 updaters.py --allow-dirty

Exit codes: 0 success or already up to date, 1 update refused or failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
REMOTE = "origin"


class UpdateError(RuntimeError):
    """Raised when the update cannot proceed safely."""


def git(*args: str) -> str:
    """Run a git command in the repository and return its stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise UpdateError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def current_branch() -> str:
    try:
        branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    except UpdateError:
        raise UpdateError("HEAD is detached; check out a branch before updating") from None
    return branch


def update(allow_dirty: bool) -> str:
    """Fast-forward the current branch to origin. Returns a human-readable summary."""
    git("rev-parse", "--is-inside-work-tree")
    branch = current_branch()
    try:
        git("remote", "get-url", REMOTE)
    except UpdateError:
        raise UpdateError(f"no '{REMOTE}' remote is configured") from None

    if not allow_dirty and git("status", "--porcelain"):
        raise UpdateError(
            "uncommitted changes present; commit or stash them, or pass --allow-dirty"
        )

    try:
        git("fetch", "--quiet", REMOTE, branch)
    except UpdateError:
        raise UpdateError(f"could not fetch {REMOTE}/{branch}; does it exist?") from None

    local = git("rev-parse", "HEAD")
    remote = git("rev-parse", "FETCH_HEAD")

    if local == remote:
        return f"{branch} is already up to date ({local[:7]})"

    if _is_ancestor(local, remote):
        git("merge", "--ff-only", "FETCH_HEAD")
        return f"updated {branch}: {local[:7]} -> {remote[:7]}"

    if _is_ancestor(remote, local):
        return f"{branch} is ahead of {REMOTE}/{branch}; nothing to pull"

    raise UpdateError(
        f"{branch} has diverged from {REMOTE}/{branch}; resolve it manually, nothing was changed"
    )


def _is_ancestor(older: str, newer: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        cwd=REPO,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def run_tests() -> int:
    """Run the unit tests with the same interpreter that is running this script."""
    print("running tests...")
    return subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=REPO)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update AntiFlag from the current branch.")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="attempt the update even with uncommitted changes",
    )
    parser.add_argument("--test", action="store_true", help="run the unit tests afterwards")
    args = parser.parse_args(argv)

    try:
        print(update(args.allow_dirty))
    except UpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.test:
        return 0 if run_tests() == 0 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
