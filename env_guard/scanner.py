"""Walks a folder (or the git index) and turns rule matches into findings."""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

from env_guard.gitignore import GitIgnore, ignored_paths
from env_guard.rules import HIGH, LOW, MEDIUM, EntropyConfig, mask, scan_text

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
             ".pytest_cache", ".mypy_cache", ".tox", ".idea", "site-packages"}
SAFE_ENV_FILES = {".env.example", ".env.sample", ".env.template"}
HIGH_RISK_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json"}
HIGH_RISK_SUFFIXES = {".pem", ".key"}
MEDIUM_RISK_SUFFIXES = {".db", ".sqlite3", ".sqlite"}
MAX_FILE_BYTES = 1_000_000
ALLOWLIST_FILE = ".envguardignore"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


class ScanError(Exception):
    """Raised when a scan can't run (e.g. --staged outside a git repository)."""


@dataclass(frozen=True)
class Finding:
    """One problem: where it is, which rule fired, how bad it is, and a masked preview."""

    path: str
    line: int | None
    rule: str
    severity: str
    preview: str

    def location(self) -> str:
        return self.path if self.line is None else f"{self.path}:{self.line}"


@dataclass
class ScanResult:
    """Everything a scan found, plus how many files were actually read."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def counts(self) -> dict[str, int]:
        counts = {HIGH: 0, MEDIUM: 0, LOW: 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def blocking(self) -> bool:
        """True when a commit should be stopped (any high or medium finding)."""
        counts = self.counts()
        return counts[HIGH] + counts[MEDIUM] > 0

    def to_dict(self) -> dict[str, object]:
        return {"files_scanned": self.files_scanned, "summary": self.counts(),
                "findings": [asdict(f) for f in self.findings]}


def risky_file_severity(path: str) -> str | None:
    """Severity for files that should never be committed, or None if the name is fine."""
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(name).suffix
    if name in SAFE_ENV_FILES:
        return None
    if name == ".env" or name.startswith(".env.") or name in HIGH_RISK_NAMES:
        return HIGH
    if suffix in HIGH_RISK_SUFFIXES:
        return HIGH
    return MEDIUM if suffix in MEDIUM_RISK_SUFFIXES else None


def is_binary(data: bytes) -> bool:
    """Treat anything with a NUL byte in the first 8 KB as binary."""
    return b"\0" in data[:8192]


def walk_files(root: Path) -> list[str]:
    """All files under root as posix paths, skipping VCS folders, venvs and node_modules."""
    files = []
    for current, dirs, names in os.walk(root):
        here = Path(current)
        dirs[:] = sorted(d for d in dirs
                         if d not in SKIP_DIRS and not (here / d / "pyvenv.cfg").exists())
        files += [(here / n).relative_to(root).as_posix() for n in sorted(names)]
    return files


def read_head(path: Path) -> bytes:
    """Read just enough of a file to scan it (or to know it is too big to bother)."""
    with path.open("rb") as handle:
        return handle.read(MAX_FILE_BYTES + 1)


def git_output(root: Path, *args: str) -> bytes:
    """Run a git command in root and return stdout, raising ScanError on failure."""
    try:
        proc = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    except OSError as exc:
        raise ScanError("git is not installed or not on PATH") from exc
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ScanError(message or f"git {args[0]} failed")
    return proc.stdout


def staged_files(root: Path) -> list[str]:
    """Paths added/modified in the index, relative to root."""
    out = git_output(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "--relative", "-z")
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def scan_content(path: str, data: bytes, entropy: EntropyConfig) -> list[Finding]:
    """Findings for one file's content (binary and huge files are skipped)."""
    if is_binary(data) or len(data) > MAX_FILE_BYTES:
        return []
    text = data.decode("utf-8", errors="replace")
    return [Finding(path, m.line, m.rule, m.severity, mask(m.secret))
            for m in scan_text(text, path, entropy)]


def _scan(paths: list[str], read: Callable[[str], bytes], entropy: EntropyConfig,
          risky_note: str) -> ScanResult:
    result = ScanResult()
    for path in paths:
        severity = risky_file_severity(path)
        if severity:
            result.findings.append(Finding(path, None, "risky-file", severity, risky_note))
        try:
            data = read(path)
        except (OSError, ScanError):
            continue  # broken symlink, submodule entry, file deleted mid-scan...
        if not is_binary(data):
            result.files_scanned += 1
        result.findings += scan_content(path, data, entropy)
    result.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line or 0))
    return result


def scan_directory(root: Path, entropy: EntropyConfig | None = None, use_git: bool = True) -> ScanResult:
    """Scan every non-ignored file under root."""
    root = Path(root)
    allow = GitIgnore.from_file(root / ALLOWLIST_FILE)
    candidates = [p for p in walk_files(root) if not allow.is_ignored(p)]
    ignored = ignored_paths(root, candidates, use_git=use_git)
    paths = [p for p in candidates if p not in ignored]
    return _scan(paths, lambda p: read_head(root / p), entropy or EntropyConfig(),
                 "not covered by .gitignore")


def scan_staged(root: Path, entropy: EntropyConfig | None = None) -> ScanResult:
    """Scan the staged version of files in the git index. Staged risky files always count."""
    root = Path(root)
    allow = GitIgnore.from_file(root / ALLOWLIST_FILE)
    paths = [p for p in staged_files(root) if not allow.is_ignored(p)]
    return _scan(paths, lambda p: git_output(root, "show", f":./{p}"), entropy or EntropyConfig(),
                 "staged for commit")
