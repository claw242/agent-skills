---
name: night-shift-guardrails-lite
description: Install a small safety hook for Claude Code that blocks three classic accidents before they run - recursive rm outside the project folder, git force pushes and git hook bypasses (the no-verify flag), and reading or editing secret files such as .env and private keys. Every refusal is written to a denial log. Use when the user wants guardrails, safety hooks, protection against destructive shell commands, or a safer setup for unattended or autonomous Claude Code runs. Pure Python standard library, no network, no telemetry.
---

# Night Shift Guardrails Lite

A PreToolUse hook (`guard.py`) that reads each tool call before it runs and refuses it with exit code 2 when it matches one of three rules. It never runs the command it inspects.

## What it blocks

1. **`rm-outside-project`**: `rm -r` / `rm -rf` (any flag order, quotes, `sudo`, `bash -c`, `eval`, `$(...)`, backticks) and `find ... -delete` aimed at a path outside the project folder, at the project root itself, or at a variable it cannot resolve.
2. **`git-force-push`** and **`git-hook-bypass`**: `git push --force`, `-f`, `--force-with-lease`, `+branch`, `--mirror`; the git hook-skipping flag on any git command, `git commit -n`, `core.hooksPath` changes, `HUSKY=0`.
3. **`secret-read`**: reading, copying or editing `.env` (and `.env.*` except `.example`, `.sample`, `.template`), private keys (`*.pem`, `*.key`, `id_rsa`, ...), `~/.ssh`, `~/.aws/credentials`, `~/.gnupg`, `.npmrc`, `.netrc`. Applies to shell readers (`cat`, `grep`, `cp`, `source`, `< .env`...) and to the Read, Edit, Write, NotebookEdit and Grep tools.

## Install (ask the user first)

Installing edits `.claude/settings.json`. Tell the user what will change and get a yes, then:

```bash
python3 <this skill folder>/guard.py --install --dry-run   # preview, writes nothing
python3 <this skill folder>/guard.py --install             # writes ./.claude/settings.json
```

`--install` keeps existing settings, saves a backup (`settings.json.bak-guardrails-lite`), is safe to run twice, and refuses to touch a settings file that is not valid JSON. Use `--settings <file>` for another settings file. A manual alternative is `hook-snippet.json` in this folder.

Then check it works, without running anything:

```bash
python3 <this skill folder>/guard.py --check "git push --force"   # BLOCK [git-force-push]
python3 <this skill folder>/guard.py --check "git status"         # ALLOW
```

Hooks load when a session starts: tell the user to restart Claude Code or open `/hooks`.

## When a command is refused

The reason is printed on stderr and appended to `<project>/.claude/guardrails-denials.jsonl` (time, tool, rule, first 200 characters of the input). Do not try to get around a refusal with another spelling: explain what was blocked and ask the user to run it themselves if it is really intended. To review what was refused: `cat .claude/guardrails-denials.jsonl`.

Options: `GUARD_ALLOW_TEMP=1` lets recursive deletes under the system temp folder through; `GUARD_LOG=<file>` moves the log.

## Limits, said plainly

A protection layer, not a sandbox. It parses command text; it does not see inside a script that an agent writes and then runs, inline `python -c` code, or secrets reached through `grep -r .` or `cat *`. Plain `rm` without `-r`, `mv` onto a file, `chmod`, `curl | sh` are not covered by this free version. It follows `cd`/`pushd`, resolves symlinks and environment variables, and refuses a path it cannot resolve (for example `cat $UNKNOWN_VAR`); `cd` and variables stay inside `( ... )`, `$( ... )`, `bash -c` and pipelines, and `$PWD` follows the tracked directory; functions and loops that change directory are not modelled. Fails closed: a crash or invalid input refuses the call.

## Made by

Made with AI assistance by Loupe & Lettres. Independent; not affiliated with or endorsed by Anthropic.

The fuller paid kit, Night Shift Guardrails, covers many more cases (pipes into a shell, uploads, database destruction, system administration, an emergency STOP file, an approval queue): https://loupeetlettres.gumroad.com/l/evxhuu
