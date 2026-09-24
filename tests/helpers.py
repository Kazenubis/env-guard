"""Test helpers. Fake secrets are assembled from pieces so this repo never contains a real-looking one."""

from __future__ import annotations

import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def fake_aws_key() -> str:
    return "AK" + "IA" + "Z7Q3" * 4


def fake_github_token() -> str:
    return "gh" + "p_" + "aB3dE5fG7h" * 3 + "J9kL1m"


def fake_github_pat() -> str:
    return "github" + "_pat_" + "11AB2CD3EF" * 3


def fake_openai_key() -> str:
    return "sk" + "-proj-" + "Ab12Cd34Ef56" + "Gh78Ij90Kl12"


def fake_slack_token() -> str:
    return "xo" + "xb-" + "1234567890-" + "abcdEF12ghIJ34kl"


def fake_google_key() -> str:
    return "AI" + "za" + "Sy" + ("B1c2D3e4F5" * 4)[:33]


def fake_jwt() -> str:
    return ".".join(["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0", "abcDEF123_" + "-xyzQRS456"])


def fake_private_key() -> str:
    header = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    footer = "-----END " + "RSA PRIVATE" + " KEY-----"
    body = [random_token(64, seed=n) for n in range(3)]
    return "\n".join([header, *body, footer])


def random_token(length: int = 40, seed: int = 7) -> str:
    """A reproducible random base64-ish token (high entropy)."""
    rng = random.Random(seed)
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(length))


def write(root: Path, rel: str, content: str | bytes) -> Path:
    """Create a file (and its parent folders) under root."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def git(root: Path, *args: str) -> None:
    """Run git quietly inside a test repository."""
    subprocess.run(["git", "-c", "init.defaultBranch=main", *args], cwd=root,
                   check=True, capture_output=True)
