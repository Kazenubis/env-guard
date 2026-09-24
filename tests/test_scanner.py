"""Folder scanning: risky files, skipping rules and the allowlist."""

import json

from env_guard.scanner import scan_directory
from helpers import fake_github_token, fake_slack_token, write


def summary(result):
    return sorted((f.path, f.rule, f.severity) for f in result.findings)


def test_risky_files_without_gitignore_are_reported(tmp_path):
    for name in (".env", "id_rsa", "certs/server.pem", "data/app.db", "credentials.json"):
        write(tmp_path, name, "placeholder\n")
    result = scan_directory(tmp_path, use_git=False)
    assert summary(result) == [
        (".env", "risky-file", "high"),
        ("certs/server.pem", "risky-file", "high"),
        ("credentials.json", "risky-file", "high"),
        ("data/app.db", "risky-file", "medium"),
        ("id_rsa", "risky-file", "high"),
    ]


def test_env_example_allowed_and_ignored_env_skipped(tmp_path):
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, ".env", "GITHUB_TOKEN=" + fake_github_token() + "\n")
    write(tmp_path, ".env.example", "GITHUB_TOKEN=your-token-here\n")
    result = scan_directory(tmp_path, use_git=False)
    assert result.findings == []
    assert result.files_scanned == 2


def test_binary_files_are_skipped(tmp_path):
    write(tmp_path, "image.png", b"\x89PNG\x00\x00" + fake_github_token().encode())
    result = scan_directory(tmp_path, use_git=False)
    assert result.findings == []
    assert result.files_scanned == 0


def test_vendor_and_venv_folders_are_skipped(tmp_path):
    token = 'TOKEN = "' + fake_github_token() + '"\n'
    write(tmp_path, "node_modules/lib/index.js", token)
    write(tmp_path, ".git/config", token)
    write(tmp_path, "myenv/pyvenv.cfg", "home = /usr/bin\n")
    write(tmp_path, "myenv/lib/site.py", token)
    write(tmp_path, "src/app.py", token)
    assert summary(scan_directory(tmp_path, use_git=False)) == [("src/app.py", "github-token", "high")]


def test_envguardignore_allowlist(tmp_path):
    write(tmp_path, ".envguardignore", "fixtures/\n")
    write(tmp_path, "fixtures/sample.txt", fake_slack_token() + "\n")
    write(tmp_path, "notes.txt", fake_slack_token() + "\n")
    assert summary(scan_directory(tmp_path, use_git=False)) == [("notes.txt", "slack-token", "high")]


def test_output_never_contains_the_full_secret(tmp_path):
    token = fake_github_token()
    write(tmp_path, "settings.py", f'TOKEN = "{token}"\n')
    report = json.dumps(scan_directory(tmp_path, use_git=False).to_dict())
    assert token not in report
    assert token[-4:] in report
