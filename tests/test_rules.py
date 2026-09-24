"""Content rules, entropy and masking."""

import pytest

from env_guard.rules import EntropyConfig, mask, scan_text, shannon_entropy
from helpers import (fake_aws_key, fake_github_pat, fake_github_token, fake_google_key, fake_jwt,
                     fake_openai_key, fake_private_key, fake_slack_token, random_token)


def rules_in(text: str, path: str = "app.py") -> list[str]:
    return [m.rule for m in scan_text(text, path)]


@pytest.mark.parametrize("make_secret, rule", [
    (fake_aws_key, "aws-access-key-id"),
    (fake_github_token, "github-token"),
    (fake_github_pat, "github-token"),
    (fake_openai_key, "openai-key"),
    (fake_slack_token, "slack-token"),
    (fake_google_key, "google-api-key"),
    (fake_jwt, "jwt"),
])
def test_named_rule_detects_secret(make_secret, rule):
    matches = scan_text(f'client = connect(token="{make_secret()}")', "app.py")
    assert [m.rule for m in matches] == [rule]
    assert matches[0].secret == make_secret()


def test_private_key_block_reports_header_once_and_skips_body():
    text = "config = 1\n" + fake_private_key() + "\nafter = 2\n"
    matches = scan_text(text, "deploy.txt")
    assert [(m.line, m.rule) for m in matches] == [(2, "private-key-block")]


def test_generic_assignment_flags_real_value_in_env_file():
    matches = scan_text("DB_PASSWORD=" + "Tr0ub4dor" + "Kx9\n", ".env")
    assert [(m.rule, m.severity) for m in matches] == [("generic-assignment", "medium")]


@pytest.mark.parametrize("line", [
    "API_KEY=your-key-here",
    "PASSWORD=changeme",
    "SECRET_KEY=${SECRET_KEY}",
    "api_key=",
    'password: "<fill me in>"',
    "AUTH_TOKEN=xxxxxxxxxxxx",
])
def test_placeholder_values_are_not_flagged(line):
    assert rules_in(line, ".env") == []


def test_code_only_counts_quoted_literals():
    assert rules_in("password = args.password\nsecret = load_secret()") == []
    assert rules_in('line = "SECRET=" + make_value() + "\\n"') == []
    assert rules_in('password = "' + "Tr0ub4dor" + 'Kx9"') == ["generic-assignment"]


def test_shannon_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_high_entropy_token_uses_configurable_threshold():
    line = "blob = " + random_token(40)
    assert rules_in(line) == ["high-entropy-string"]
    assert scan_text(line, "app.py", EntropyConfig(base64_threshold=6.0)) == []
    assert scan_text(line, "app.py", EntropyConfig(enabled=False)) == []
    assert rules_in("name = " + "a1" * 20) == []


def test_ordinary_code_is_clean():
    code = 'def test_generic_assignment_in_code(tmp_path):\n    url = "https://example.com/v2/items"\n'
    assert rules_in(code) == []


def test_mask_keeps_only_edges():
    token = fake_github_token()
    masked = mask(token)
    assert masked == "ghp_" + "*" * 16 + token[-4:]
    assert token not in masked
    assert mask("hunter2pass") == "hu*******ss"
    assert mask("abc") == "***"


def test_inline_ignore_comment_silences_line():
    line = 'TOKEN = "' + fake_github_token() + '"'
    assert rules_in(line) == ["github-token"]
    assert rules_in(line + "  # envguard: ignore") == []
