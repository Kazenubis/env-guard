"""A small .gitignore matcher, plus a `git check-ignore` wrapper that falls back to it."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IgnoreRule:
    """One compiled line of a .gitignore file."""

    regex: re.Pattern[str]
    negated: bool
    dir_only: bool


def glob_to_regex(glob: str) -> str:
    """Translate a gitignore glob (`*`, `?`, `**`, `[abc]`) into a regex body."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        elif glob[i] == "[" and "]" in glob[i + 1:]:
            end = glob.index("]", i + 1)
            body = glob[i + 1:end].replace("\\", "\\\\")
            out.append("[" + ("^" + body[1:] if body.startswith("!") else body) + "]")
            i = end + 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return "".join(out)


def compile_rule(line: str) -> IgnoreRule | None:
    """Compile one .gitignore line, or return None for blanks and comments."""
    line = line.rstrip("\n").rstrip()
    if not line or line.startswith("#"):
        return None
    negated = line.startswith("!")
    if negated or line.startswith("\\"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    anchored = "/" in line
    line = line.lstrip("/")
    if not line:
        return None
    prefix = "" if anchored else "(?:.*/)?"
    return IgnoreRule(re.compile(f"^{prefix}{glob_to_regex(line)}$"), negated, dir_only)


class GitIgnore:
    """Answers "is this path ignored?" for paths relative to the folder holding the patterns."""

    def __init__(self, lines: list[str] | tuple[str, ...] = ()) -> None:
        self.rules = [rule for rule in map(compile_rule, lines) if rule]

    @classmethod
    def from_file(cls, path: Path) -> GitIgnore:
        """Load patterns from a file; a missing file means nothing is ignored."""
        if not path.is_file():
            return cls()
        return cls(path.read_text(encoding="utf-8", errors="replace").splitlines())

    def _last_match(self, path: str, is_dir: bool) -> bool:
        ignored = False
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(path):
                ignored = not rule.negated
        return ignored

    def is_ignored(self, path: str, is_dir: bool = False) -> bool:
        """Last matching rule wins; a file inside an ignored folder can't be re-included."""
        parts = path.strip("/").split("/")
        for depth in range(1, len(parts)):
            if self._last_match("/".join(parts[:depth]), is_dir=True):
                return True
        return self._last_match("/".join(parts), is_dir)


def git_check_ignore(root: Path, paths: list[str]) -> set[str] | None:
    """Ask git which paths are ignored. Returns None when git or the repo isn't available."""
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "--stdin", "-z"],
            input="\0".join(paths).encode("utf-8"), cwd=root, capture_output=True, check=False,
        )
    except OSError:
        return None
    if proc.returncode not in (0, 1):
        return None
    return {p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p}


def ignored_paths(root: Path, paths: list[str], use_git: bool = True) -> set[str]:
    """Return the subset of `paths` that git would ignore (git first, own matcher as fallback)."""
    if not paths:
        return set()
    if use_git:
        result = git_check_ignore(root, paths)
        if result is not None:
            return result
    matcher = GitIgnore.from_file(root / ".gitignore")
    return {p for p in paths if matcher.is_ignored(p)}
