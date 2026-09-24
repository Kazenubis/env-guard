"""The fallback .gitignore matcher and the git check-ignore wrapper."""

import pytest

from env_guard.gitignore import GitIgnore, ignored_paths
from helpers import git, needs_git, write


@pytest.mark.parametrize("patterns, path, is_dir, expected", [
    (["*.log"], "logs/app.log", False, True),
    (["/build"], "build/out.txt", False, True),
    (["/build"], "src/build/out.txt", False, False),
    (["docs/"], "docs/readme.md", False, True),
    (["docs/"], "docs", False, False),
    (["**/secret.txt"], "a/b/secret.txt", False, True),
    (["a/**/z.txt"], "a/b/c/z.txt", False, True),
    (["config/*.json"], "config/deep/app.json", False, False),
    ([".env*", "!.env.example"], ".env.example", False, False),
    ([".env*", "!.env.example"], ".env.local", False, True),
    (["logs/", "!logs/keep.txt"], "logs/keep.txt", False, True),
    (["# comment", "", "*.pyc"], "pkg/mod.pyc", False, True),
])
def test_gitignore_matcher(patterns, path, is_dir, expected):
    assert GitIgnore(patterns).is_ignored(path, is_dir) is expected


def test_fallback_reads_gitignore_file(tmp_path):
    write(tmp_path, ".gitignore", ".env\n*.db\n")
    paths = [".env", "app.db", "main.py"]
    assert ignored_paths(tmp_path, paths, use_git=False) == {".env", "app.db"}


@needs_git
def test_git_check_ignore_is_preferred_in_a_repo(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, ".gitignore", "secrets/\n")
    assert ignored_paths(tmp_path, ["secrets/prod.env", "main.py"]) == {"secrets/prod.env"}
