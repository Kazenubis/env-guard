"""Content rules: named secret patterns, Shannon entropy and masking."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

HIGH, MEDIUM, LOW = "high", "medium", "low"

IGNORE_MARK = re.compile(r"envguard:\s*ignore", re.IGNORECASE)
KEY_BLOCK_START = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----")
KEY_BLOCK_END = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----")


@dataclass(frozen=True)
class Rule:
    """A named regex rule. `group` selects the part of the match that is the secret."""

    name: str
    severity: str
    pattern: re.Pattern[str]
    group: int = 0


@dataclass(frozen=True)
class LineMatch:
    """A secret found on a single line (before it is tied to a file)."""

    line: int
    rule: str
    severity: str
    secret: str


@dataclass(frozen=True)
class EntropyConfig:
    """Thresholds for the high-entropy check (bits per character)."""

    base64_threshold: float = 4.3
    hex_threshold: float = 3.0
    min_length: int = 20
    enabled: bool = True


RULES: tuple[Rule, ...] = (
    Rule("aws-access-key-id", HIGH, re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    Rule("github-token", HIGH,
         re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), 1),
    Rule("openai-key", HIGH, re.compile(r"\b(sk-(?:proj-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,})"), 1),
    Rule("slack-token", HIGH, re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"), 1),
    Rule("google-api-key", HIGH, re.compile(r"\b(AIza[0-9A-Za-z_-]{35})"), 1),
    Rule("private-key-block", HIGH, KEY_BLOCK_START),
    Rule("jwt", MEDIUM,
         re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), 1),
)

ASSIGNMENT = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
    r"[A-Za-z0-9_]*)[\"']?\s*[:=](?!=)\s*(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;#]+)",
    re.IGNORECASE,
)
PLACEHOLDER_HINTS = (
    "your", "example", "changeme", "change-me", "change_me", "placeholder", "xxx", "dummy",
    "sample", "fake", "redacted", "here", "test", "***", "<", ">", "${", "{{", "%(", "$(",
)
PLACEHOLDER_WORDS = {"none", "null", "true", "false", "password", "secret", "empty", "required"}
CONFIG_SUFFIXES = {"", ".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml",
                   ".json", ".sh", ".bash", ".ps1", ".bat", ".cmd"}

TOKEN = re.compile(r"[A-Za-z0-9+/_-]{2,}={0,2}")
HEX = re.compile(r"[0-9a-fA-F]+")


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of `text` in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in Counter(text).values())


def mask(secret: str, keep: int = 4, max_stars: int = 16) -> str:
    """Hide the middle of a secret, e.g. 'ghp_****************abcd'. Short values show less."""
    keep = min(keep, len(secret) // 5)
    if keep == 0:
        return "*" * min(len(secret), max_stars)
    stars = min(len(secret) - keep * 2, max_stars)
    return f"{secret[:keep]}{'*' * stars}{secret[-keep:]}"


def is_placeholder(value: str) -> bool:
    """True for values that are obviously not real secrets (empty, templated, 'your-key-here'...)."""
    lowered = value.strip().lower()
    if len(lowered) < 6 or lowered in PLACEHOLDER_WORDS or len(set(lowered)) <= 2:
        return True
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def is_config_like(path: str) -> bool:
    """Config/env files allow unquoted secrets; in code only quoted literals count."""
    name = PurePosixPath(path).name.lower()
    return name.startswith(".env") or PurePosixPath(name).suffix in CONFIG_SUFFIXES


def assignment_secrets(line: str, config_like: bool) -> list[str]:
    """Values from `password=` / `secret:` / `api_key=` style assignments that look real."""
    found = []
    for match in ASSIGNMENT.finditer(line):
        value = match.group("value")
        quoted = value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2
        if not quoted and not config_like:
            continue
        value = value[1:-1] if quoted else value
        if value != value.strip():
            continue  # e.g. `"KEY=" + name + "..."`: the "value" is code between two literals
        if not is_placeholder(value):
            found.append(value)
    return found


def high_entropy_tokens(line: str, config: EntropyConfig) -> list[str]:
    """Base64/hex-looking tokens whose entropy is above the configured threshold."""
    hits = []
    for token in TOKEN.findall(line):
        if len(token) < config.min_length or not re.search(r"\d", token):
            continue
        if HEX.fullmatch(token):
            if re.search(r"[a-fA-F]", token) and shannon_entropy(token) >= config.hex_threshold:
                hits.append(token)
        elif re.search(r"[A-Za-z]", token) and shannon_entropy(token) >= config.base64_threshold:
            hits.append(token)
    return hits


def scan_text(text: str, path: str = "", entropy: EntropyConfig | None = None) -> list[LineMatch]:
    """Run every content rule over `text` and return the matches, line by line."""
    entropy = entropy or EntropyConfig()
    config_like = is_config_like(path)
    matches: list[LineMatch] = []
    in_key_block = False
    for number, line in enumerate(text.splitlines(), start=1):
        if in_key_block:
            in_key_block = not KEY_BLOCK_END.search(line)
            continue
        if IGNORE_MARK.search(line):
            continue
        found = [LineMatch(number, r.name, r.severity, m.group(r.group))
                 for r in RULES for m in r.pattern.finditer(line)]
        found += [LineMatch(number, "generic-assignment", MEDIUM, v)
                  for v in assignment_secrets(line, config_like)
                  if not any(f.secret in v for f in found)]
        if not found and entropy.enabled:
            found = [LineMatch(number, "high-entropy-string", LOW, t)
                     for t in high_entropy_tokens(line, entropy)]
        in_key_block = any(m.rule == "private-key-block" for m in found)
        matches.extend(found)
    return matches
