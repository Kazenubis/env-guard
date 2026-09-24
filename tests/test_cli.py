"""CLI behaviour: output formats, exit codes, --staged and install-hook."""

import json

from env_guard.cli import main
from helpers import fake_aws_key, fake_github_token, git, needs_git, random_token, write


def test_json_output_shape(tmp_path, capsys):
    write(tmp_path, "config.py", 'AWS_ID = "' + fake_aws_key() + '"\n')
    code = main(["scan", str(tmp_path), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert set(data) == {"files_scanned", "summary", "findings"}
    assert data["summary"] == {"high": 1, "medium": 0, "low": 0}
    assert data["findings"][0] == {"path": "config.py", "line": 1, "rule": "aws-access-key-id",
                                   "severity": "high", "preview": "AKIA" + "*" * 12 + "Z7Q3"}


def test_exit_codes(tmp_path, capsys):
    write(tmp_path, "main.py", "print('hello')\n")
    assert main(["scan", str(tmp_path)]) == 0
    assert "No secrets found in 1 file." in capsys.readouterr().out

    write(tmp_path, "blob.txt", random_token(40) + "\n")
    assert main(["scan", str(tmp_path)]) == 0, "low findings alone must not block a commit"

    write(tmp_path, ".env", "SECRET=" + random_token(24, seed=3) + "\n")
    assert main(["scan", str(tmp_path)]) == 1
    assert "Commit blocked." in capsys.readouterr().out


@needs_git
def test_staged_scans_only_what_is_staged(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, ".env", "PASSWORD=" + random_token(20) + "\n")
    write(tmp_path, "unstaged.py", 'TOKEN = "' + fake_github_token() + '"\n')
    write(tmp_path, "app.py", "print('ok')\n")
    git(tmp_path, "add", "app.py", ".gitignore")
    assert main(["scan", str(tmp_path), "--staged"]) == 0
    capsys.readouterr()

    git(tmp_path, "add", "-f", ".env")
    assert main(["scan", str(tmp_path), "--staged", "--format", "json"]) == 1
    rules = {(f["path"], f["rule"]) for f in json.loads(capsys.readouterr().out)["findings"]}
    assert rules == {(".env", "risky-file"), (".env", "generic-assignment")}


def test_staged_outside_git_repo_is_an_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--staged"]) == 2
    assert "env_guard:" in capsys.readouterr().err


def test_install_hook_refuses_to_overwrite(tmp_path, capsys):
    hook = write(tmp_path, ".git/hooks/pre-commit", "#!/bin/sh\necho mine\n")
    assert main(["install-hook", str(tmp_path)]) == 2
    assert "--force" in capsys.readouterr().err
    assert hook.read_text() == "#!/bin/sh\necho mine\n"

    assert main(["install-hook", str(tmp_path), "--force"]) == 0
    assert "-m env_guard scan . --staged" in hook.read_text()


def test_install_hook_needs_a_git_repo(tmp_path):
    assert main(["install-hook", str(tmp_path)]) == 2
