# Env Guard

A small, stdlib-only Python CLI that scans a project (or just your staged files) for secrets and risky files before you commit.

## Why I built this

Early on I pushed a `.env` file to GitHub by accident, with real keys inside. Since then I follow a hygiene-first git routine: write the `.gitignore` before anything else, and run `git status` before every commit. Env Guard automates the part I could still get wrong: checking what is actually going into the commit.

## Features

- Flags risky files that git would commit: `.env` and `.env.*` (but not `.env.example`), `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `*.db` / `*.sqlite3`.
- Works out "ignored" with `git check-ignore` inside a repo, and falls back to its own `.gitignore` matcher (`*`, `**`, trailing `/`, leading `/`, `!` negation) when git isn't there.
- Named content rules: AWS access key IDs, GitHub tokens (`ghp_`, `github_pat_`), OpenAI-style `sk-` keys, Slack tokens, Google API keys, private key blocks, JWTs, and `password=` / `secret=` / `api_key=` assignments. Placeholders like `API_KEY=your-key-here` are ignored.
- High-entropy check (Shannon entropy) for base64- and hex-looking tokens of 20+ characters, with adjustable thresholds.
- Never prints a full secret. Previews are masked, e.g. `ghp_****************2eUk`.
- Skips binary files, `.git/`, virtualenvs and `node_modules/`. Supports a `.envguardignore` allowlist and inline `# envguard: ignore` comments.
- `--staged` scans only what `git add` staged. `--format json` gives output other tools can read. The exit code is 1 on high or medium findings, so it works as a pre-commit hook.

## Run it

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m env_guard scan .
```

Scanning a small side project that forgot to ignore its `.env`:

```
> python -m env_guard scan ..\weather-bot
HIGH    .env             risky-file           not covered by .gitignore
HIGH    bot.py:4         github-token         ghp_****************2eUk
MEDIUM  forecast.db      risky-file           not covered by .gitignore
MEDIUM  settings.yaml:3  generic-assignment   S3*******5!
LOW     .env:1           high-entropy-string  9f3c****************0864
5 findings (2 high, 2 medium, 1 low) in 5 files. Commit blocked.
```

Other options:

```
python -m env_guard scan . --staged          # only files staged with git add
python -m env_guard scan . --format json     # machine-readable output
python -m env_guard scan . --entropy-base64 4.5 --entropy-hex 3.5
python -m env_guard scan . --no-entropy
```

Exit codes: `0` means clean (low findings don't block), `1` means at least one high or medium finding, and `2` means a usage error, such as `--staged` outside a git repository.

Files that match a pattern in `.envguardignore` (same syntax as `.gitignore`) are skipped. To skip a single line, add `# envguard: ignore` to it.

### Use it as a pre-commit hook

This is my routine for every commit in the `weather-bot` project:

```
> git status --short
A  .env.example
A  .gitignore
A  bot.py
A  settings.yaml
> python -m env_guard scan . --staged
No secrets found in 4 files. Safe to commit.
> git commit -m "first commit"
```

To make the check automatic, install the hook once from the project's root, with the Env Guard venv active:

```
> python -m env_guard install-hook
Installed pre-commit hook at .git/hooks/pre-commit
```

The hook runs `scan . --staged` on every `git commit`. It uses the Python interpreter and the Env Guard folder that were active when you installed it, so re-run `install-hook --force` if you move either of them. It won't replace a hook that already exists unless you pass `--force`. If I force-add the `.env` by mistake, the commit stops:

```
> git add -f .env
> git commit -m "oops"
HIGH    .env    risky-file           staged for commit
LOW     .env:1  high-entropy-string  9f3c****************0864
2 findings (1 high, 0 medium, 1 low) in 1 file. Commit blocked.
```

## Run the tests

```
python -m pytest -q
```

## Project structure

```
env-guard/
├── env_guard/
│   ├── __init__.py
│   ├── __main__.py     # python -m env_guard
│   ├── cli.py          # argparse subcommands, text/JSON output, exit codes
│   ├── scanner.py      # folder walk, --staged via git, risky-file check, findings
│   ├── rules.py        # named regex rules, placeholder filter, entropy, masking
│   ├── gitignore.py    # .gitignore matcher + git check-ignore wrapper
│   └── hook.py         # pre-commit hook installer
├── tests/              # pytest suite (fake secrets are built at runtime)
├── .envguardignore
├── .gitignore
├── requirements.txt
├── README.md
└── LICENSE
```

## What I practiced

- Translating gitignore globs (`*`, `**`, anchors, directory-only patterns) into regexes, with "last match wins" negation and the rule that a file inside an ignored folder can't be re-included.
- Shannon entropy as a signal for random-looking tokens, and choosing thresholds that catch keys without flagging ordinary identifiers.
- Driving git from Python with `subprocess`: `check-ignore --stdin -z`, `diff --cached --name-only`, and `show :path` to read the staged version of a file.
- Cutting down false positives: placeholder detection, only quoted literals in code, and skipping the body of a private key block after reporting its header.
- Testing a secret scanner without committing secrets: each fake key is built by string concatenation, and the repo scans itself clean.
