"""Installs a git pre-commit hook that runs `env_guard scan . --staged`."""

from __future__ import annotations

import sys
from pathlib import Path

HOOK_TEMPLATE = """#!/bin/sh
# Installed by env-guard: blocks the commit if staged files contain secrets.
# Skip it once (only when you are sure) with: git commit --no-verify
PYTHONPATH="{package_parent}" exec "{python}" -m env_guard scan . --staged
"""


class HookError(Exception):
    """Raised when the hook can't be installed."""


def render_hook(python: str | None = None, package_parent: Path | None = None) -> str:
    """Build the hook script, pinned to this interpreter and this copy of env_guard."""
    python = python or Path(sys.executable).as_posix()
    package_parent = package_parent or Path(__file__).resolve().parent.parent
    return HOOK_TEMPLATE.format(python=python, package_parent=package_parent.as_posix())


def install_hook(repo: Path, force: bool = False) -> Path:
    """Write .git/hooks/pre-commit. Refuses to replace an existing hook unless `force` is set."""
    git_dir = Path(repo) / ".git"
    if not git_dir.is_dir():
        raise HookError(f"{Path(repo).resolve()} is not the root of a git repository (no .git folder)")
    hook = git_dir / "hooks" / "pre-commit"
    if hook.exists() and not force:
        raise HookError(f"{hook} already exists; re-run with --force to replace it")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(render_hook(), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    return hook
