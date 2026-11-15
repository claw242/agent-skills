# agent-skills

Free, small skills for AI coding agents. Today: one.

## night-shift-guardrails-lite

A safety hook for Claude Code that blocks three classic accidents **before** the command runs:

| Rule | Blocks |
| --- | --- |
| `rm-outside-project` | `rm -rf` (and `find -delete`) aimed outside the project folder, at the project root, or at a variable it cannot resolve |
| `git-force-push` / `git-hook-bypass` | `git push --force`, `-f`, `--force-with-lease`, `+branch`; the hook-skipping flag (`--no-verify`), `git commit -n`, `core.hooksPath` changes, `HUSKY=0` |
| `secret-read` | reading or editing `.env` (not `.env.example`), private keys, `~/.ssh`, `~/.aws/credentials`, `.npmrc`, `.netrc` |

It also catches the usual disguises: quotes (`r"m"`), `;` and `&&` chains, `$(...)` and backticks, `bash -c`, `eval`, `sudo`, `env`, `xargs`, simple variable assignments, here-documents. It follows `cd` / `pushd` (a path it cannot resolve is refused), resolves symlinks and environment variables before judging a path, and refuses `cat $UNKNOWN_VAR` because it cannot tell what would be read. Each refusal is written to `.claude/guardrails-denials.jsonl`.

Pure Python standard library (tested on Python 3.13). No network, no telemetry. It never runs the command it inspects. It fails closed: a crash or invalid input refuses the call.

### Install

With the skills CLI:

```bash
npx skills add claw242/agent-skills
```

Or copy `skills/night-shift-guardrails-lite/` into `.claude/skills/` of your project. Then register the hook (backup of your settings is saved, running it twice is safe):

```bash
python3 .claude/skills/night-shift-guardrails-lite/guard.py --install --dry-run   # preview
python3 .claude/skills/night-shift-guardrails-lite/guard.py --install
```

Restart Claude Code (hooks load at session start). Try it without running anything:

```bash
python3 .claude/skills/night-shift-guardrails-lite/guard.py --check "git push --force"   # BLOCK
python3 .claude/skills/night-shift-guardrails-lite/guard.py --check "git status"         # ALLOW
```

Options: `GUARD_ALLOW_TEMP=1` allows recursive deletes under the system temp folder; `GUARD_LOG=<file>` moves the log.

### Test

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

About 90 dangerous and normal commands are analysed as text, never executed.

### Limits

A protection layer, not a sandbox. It reads command text. It does not see inside a script an agent writes and then runs, inline `python -c` code, or secrets reached through `grep -r .` or `cat *`. Plain `rm` without `-r`, `chmod`, `curl | sh` are not covered by this free version. `cd` and variables stay inside `( ... )`, `$( ... )`, `bash -c` and pipelines (as in the shell); `$PWD` follows the tracked directory. Other shell flow (functions, `case`, loops that change directory) is not modelled. False positives are possible (for example `cat $FILE` with a variable it cannot resolve): in that case the agent is told to ask you to run the command yourself. Developed and tested on macOS; Linux is not tested.

Made with AI assistance by Loupe & Lettres (created with the help of AI). Independent; not affiliated with or endorsed by Anthropic. MIT license.

## Need more than three rules?

Night Shift Guardrails is a larger paid kit for the same job (pipes into a shell, uploads, database destruction, system administration, an emergency STOP file, an approval queue): https://loupeetlettres.gumroad.com/l/evxhuu
