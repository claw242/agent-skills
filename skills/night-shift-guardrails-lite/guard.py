#!/usr/bin/env python3
"""Night Shift Guardrails Lite - a small PreToolUse hook for Claude Code.

It reads the hook JSON on stdin and can only REFUSE a tool call (exit code 2, reason on stderr).
It never runs the command it inspects. Python standard library only.

Three blocks:
  1. recursive `rm` (and `find -delete`) aimed outside the project folder
  2. force pushes and git hook bypasses (the no-verify flag, core.hooksPath)
  3. reading or editing secret files (.env, private keys, cloud credentials)

Every refusal is appended to <project>/.claude/guardrails-denials.jsonl.

Usage:
  guard.py                              hook mode (reads JSON on stdin)
  guard.py --check "COMMAND"            dry run: prints the verdict, runs nothing
  guard.py --install [--settings FILE]  add the hook to .claude/settings.json

A protection layer, not a sandbox: see README.md for the limits.
"""
import argparse
import fnmatch
import json
import os
import re
import shlex
import sys
import tempfile
import time

VERSION = "0.1.0"
MAX_DEPTH = 5
MAX_COMMAND_CHARS = 100000
LOG_NAME = "guardrails-denials.jsonl"
MATCHER = "Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep"
PUNCT = ";&|()<>\n"
SEPARATORS = set(";&|()\n")
HEREDOC = re.compile(
    r"(?<!<)<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1([^\n]*)\n.*?\n[ \t]*\2[ \t]*(?=\n|$)", re.S)
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "doas", "env", "command", "nohup", "time", "nice", "exec", "builtin", "xargs", "stdbuf",
            "timeout"}
WRAPPER_ARG_OPTS = {"sudo": {"-u", "-g", "-h", "-p", "-r", "-t", "-C", "-D", "-U"}, "env": {"-u", "-C", "-S"},
                    "nice": {"-n"}, "xargs": {"-I", "-n", "-P", "-L", "-s", "-d", "-E"}, "timeout": {"-s", "-k"},
                    "stdbuf": {"-i", "-o", "-e"}, "doas": {"-u", "-C"}}
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
BYPASS_ENV = {"HUSKY": "0"}
READERS = {"cat", "less", "more", "head", "tail", "bat", "nl", "tac", "od", "xxd", "hexdump", "strings", "base64",
           "grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "cut", "sort", "uniq", "diff", "cmp", "cp", "mv",
           "scp", "rsync", "source", ".", "open", "code", "vim", "vi", "nano", "emacs", "jq", "yq", "tee", "curl",
           "wget", "zip", "tar", "gzip", "openssl", "ssh-add", "gpg"}
STRICT_READERS = {"cat", "less", "more", "head", "tail", "bat", "nl", "tac", "od", "xxd", "hexdump", "strings",
                  "base64", "cut", "sort", "uniq", "diff", "cmp", "cp", "mv", "scp", "rsync", "source", ".", "open",
                  "code", "vim", "vi", "nano", "emacs", "jq", "yq", "grep", "egrep", "fgrep", "rg", "ag", "sed", "awk"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "sed", "awk"}
SAFE_ENV_SUFFIXES =(".example", ".sample", ".template", ".dist", ".defaults")
SECRET_BASENAMES = {".npmrc", ".netrc", ".pgpass", "credentials", "credentials.json", "id_rsa", "id_dsa",
                    "id_ecdsa", "id_ed25519", "service-account.json", "secrets.json", "secrets.yml",
                    "secrets.yaml", ".htpasswd"}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")
SECRET_DIR_RE = re.compile(r"(^|/)(\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.config/gcloud)/")
PUBLIC_IN_SECRET_DIRS = {"known_hosts", "config"}
GLOB_CANDIDATES = (".env", ".env.local", ".env.production", ".npmrc", ".netrc", "id_rsa", "id_ed25519",
                   "server.pem", "server.key", "credentials", "secrets.yml")
NO_VERIFY = "--no-" + "verify"


class Verdict:
    """Findings collected for one hook call (rule, reason), without duplicates."""

    def __init__(self):
        self.findings = []

    def add(self, rule, reason):
        item = (rule, reason)
        if item not in self.findings:
            self.findings.append(item)


# ---------------------------------------------------------------- parsing
def _fallback_tokens(text):
    raw = re.findall(r"[;&|()\n]+|[<>]+|[^\s;&|()<>]+", text)
    return [t if t[0] in PUNCT else t.replace("'", "").replace('"', "") for t in raw]


def tokenize(text):
    """Split a shell command line into words and operators. Never raises."""
    text = HEREDOC.sub(lambda m: "<< HEREDOC" + m.group(3), text)
    text = re.sub(r"[<>]\(", "(", text)
    text = re.sub(r"`([^`]*)`", r"$(\1)", text)  # backticks are a command substitution too
    lex = shlex.shlex(text, posix=True, punctuation_chars=PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return _fallback_tokens(text)


def isolating(token):
    """True for | and a lone & : both sides run in their own subshell, so a cd there does not persist."""
    rest = token.replace("&&", "").replace("||", "")
    return "|" in rest or "&" in rest


def split_segments(tokens):
    """Turn tokens into events: ("cmd", words, reads, isolated), ("push",) and ("pop",).

    push/pop mark a subshell or a command substitution; a command substitution hands
    the placeholder word "$(...)" back to the outer command.
    """
    events, frames, words, reads, piped = [], [], [], [], False

    def emit(found_words, found_reads, isolated):
        if found_words or found_reads:
            events.append(("cmd", found_words, found_reads, isolated))

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if set(tok) <= SEPARATORS:
            isolated = piped or isolating(tok)
            for ch in tok:
                if ch == "(" and tok == "(" and words and words[-1] == "$":
                    frames.append((words[:-1] + ["$(...)"], reads))
                    words, reads = [], []
                    events.append(("push",))
                    continue
                emit(words, reads, isolated)
                words, reads = [], []
                if ch == "(":
                    frames.append(None)
                    events.append(("push",))
                elif ch == ")":
                    events.append(("pop",))
                    frame = frames.pop() if frames else None
                    if frame:
                        words, reads = frame
            piped = isolating(tok)
        elif set(tok) <= set("<>&") and ("<" in tok or ">" in tok):
            if tok == "<" and i + 1 < len(tokens):
                reads.append(tokens[i + 1])
            i += 1  # the redirect target is never a command word
        else:
            words.append(tok)
        i += 1
    emit(words, reads, piped)
    for frame in reversed(frames):
        if frame:
            emit(frame[0], frame[1], False)
    return events


def find_substitutions(text):
    """Inner text of $(...) and backticks, even inside double quotes."""
    found = [m.group(1) for m in re.finditer(r"`([^`]+)`", text)]
    i = 0
    while True:
        start = text.find("$(", i)
        if start < 0:
            break
        depth, j = 1, start + 2
        while j < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        found.append(text[start + 2:j - 1] if depth == 0 else text[start + 2:])
        i = start + 2
    return found


# ---------------------------------------------------------------- paths
def project_root(payload_cwd):
    return os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or payload_cwd or os.getcwd())


def expand(word, variables, root, pwd=None):
    """Expand ~ and the variables we know. PWD is the tracked directory (unknown after an unclear cd).
    Returns None when a variable stays unknown."""
    home = os.path.expanduser("~")
    known = dict(os.environ)  # the hook runs with the same environment as the shell it guards
    known.update(variables)
    known.update({"HOME": home, "CLAUDE_PROJECT_DIR": root})
    known.pop("OLDPWD", None)
    if pwd:
        known["PWD"] = pwd
    else:
        known.pop("PWD", None)
    out = home + word[1:] if word == "~" or word.startswith("~/") else word
    out = re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: known.get(m.group(1) or m.group(2), m.group(0)), out)
    return None if ("$" in out or "`" in out) else out


def is_under(path, base):
    path, base = os.path.realpath(path), os.path.realpath(base)
    return path != base and path.startswith(base.rstrip(os.sep) + os.sep)


def outside_reason(word, cwd, root, variables, allow_root=False):
    """Why `word` is unsafe as a recursive-delete target, or None if it stays inside the project."""
    expanded = expand(word, variables, root, cwd)
    if expanded is None:
        return "target %r uses a variable or substitution that cannot be checked" % word
    if cwd is None and not os.path.isabs(expanded):
        return "target %r is relative to a directory that cannot be determined after cd" % word
    target = os.path.realpath(os.path.normpath(os.path.join(cwd or "/", expanded)))
    if os.environ.get("GUARD_ALLOW_TEMP") == "1" and any(is_under(target, t) for t in {tempfile.gettempdir(), "/tmp"}):
        return None
    if target == os.path.realpath(root) and not allow_root:
        return "recursive delete of %r is the project root itself" % word
    if target != os.path.realpath(root) and not is_under(target, root):
        return "recursive delete of %r is outside the project (%s)" % (word, target)
    return None


def secret_reason(word, cwd, root, variables, strict=False):
    """Why `word` looks like a secret file, or None. `strict` refuses a path that cannot be resolved."""
    expanded = expand(word, variables, root, cwd)
    if expanded is None:
        return "%r uses a variable or substitution that cannot be checked" % word if strict else None
    if not expanded or expanded.startswith("-"):
        return None
    lexical = os.path.normpath(os.path.join(cwd or root, expanded))
    for path in dict.fromkeys([lexical, os.path.realpath(lexical)]):  # also what a symlink points to
        reason = _secret_path_reason(path, word, root)
        if reason:
            return reason
    return None


def _secret_path_reason(path, word, root):
    base = os.path.basename(path)
    if re.search(r"(^|/)proc/[^/]+/environ$", path):
        return "process environment %r may hold secrets" % word
    if base.endswith(".pub"):
        return None
    if SECRET_DIR_RE.search(path + "/") and base not in PUBLIC_IN_SECRET_DIRS:
        return "%r is in a secrets folder" % word
    if base == ".env" or (base.startswith(".env.") and not base.endswith(SAFE_ENV_SUFFIXES)):
        return "%r is an environment file with secrets" % word
    if base in SECRET_BASENAMES or base.endswith(SECRET_SUFFIXES):
        return "%r looks like a credential or private key" % word
    if base.startswith(".") and any(c in base for c in "*?["):
        for name in GLOB_CANDIDATES:
            if fnmatch.fnmatchcase(name, base) and secret_reason(name, "/", root, {}):
                return "pattern %r can match a secret file (%s)" % (word, name)
    return None


# ---------------------------------------------------------------- rules
def short_flags(words):
    return [w[1:] for w in words if w.startswith("-") and not w.startswith("--") and len(w) > 1]


def check_rm(args, ctx):
    recursive = any("r" in f.lower() for f in short_flags(args)) or "--recursive" in args
    if not recursive:
        return
    targets, after_dashes = [], False
    for w in args:
        if w == "--" and not after_dashes:
            after_dashes = True
        elif after_dashes or not w.startswith("-"):
            targets.append(w)
    for target in targets:
        reason = outside_reason(target, current_dir(ctx), ctx["root"], ctx["vars"])
        if reason:
            ctx["verdict"].add("rm-outside-project", reason)


def check_find(args, ctx):
    deletes = "-delete" in args or (("-exec" in args or "-execdir" in args)
                                    and any(w in ("rm", "rmdir", "shred") for w in args))
    if not deletes:
        return
    starts = []
    for w in args:
        if w.startswith("-") or w in ("(", "!"):
            break
        starts.append(w)
    for start in starts or ["."]:
        reason = outside_reason(start, current_dir(ctx), ctx["root"], ctx["vars"], allow_root=True)
        if reason:
            ctx["verdict"].add("rm-outside-project", "find deleting files: " + reason)


def git_parts(args):
    """Return (global_options, subcommand, subcommand_args)."""
    i, opts = 0, []
    while i < len(args) and args[i].startswith("-"):
        opts.append(args[i])
        if args[i] in GIT_OPTS_WITH_ARG and i + 1 < len(args):
            opts.append(args[i + 1])
            i += 1
        i += 1
    return opts, (args[i] if i < len(args) else ""), args[i + 1:]


def check_git(args, ctx):
    opts, sub, rest = git_parts(args)
    add = ctx["verdict"].add
    if any("hookspath" in o.lower() for o in opts) or (sub == "config" and any("hookspath" in a.lower() for a in rest)):
        add("git-hook-bypass", "changing core.hooksPath would bypass the git hooks")
    if NO_VERIFY in rest:
        add("git-hook-bypass", "%s skips the git hooks" % NO_VERIFY)
    if sub == "commit" and any(re.match(r"^[^mFcCS]*n", f) for f in short_flags(rest) if f.isalpha()):
        add("git-hook-bypass", "git commit -n skips the git hooks")
    if sub == "push":
        forced = [a for a in rest if a in ("--force", "-f", "--mirror")
                  or a.startswith(("--force-with-lease", "--force-if-includes"))
                  or re.match(r"^-[a-zA-Z]*f[a-zA-Z]*$", a) or (a.startswith("+") and len(a) > 1)]
        if forced:
            add("git-force-push", "force push is not allowed (%s)" % forced[0])


def current_dir(ctx):
    """The directory the next command runs in, or None when a cd made it unknown."""
    return ctx["cwd"] if ctx["cwd_known"] else None


def change_directory(cmd, args, ctx):
    """Follow cd / pushd so that later relative paths are checked from the right place."""
    targets = [a for a in args if not a.startswith("-") or a == "-"]
    first = targets[0] if targets else "~"
    expanded = None if (cmd == "popd" or first == "-" or first.startswith("+")) else expand(first, ctx["vars"], ctx["root"], current_dir(ctx))
    base = ctx["cwd"] if ctx["cwd_known"] else None
    if expanded is None or (base is None and not os.path.isabs(expanded)):
        ctx["cwd_known"] = False
        return
    ctx["cwd"] = os.path.realpath(os.path.normpath(os.path.join(base or "/", expanded)))
    ctx["cwd_known"] = True


def positional_args(cmd, args):
    """Arguments that are file paths: drops options and, for grep/sed/awk, the pattern or script."""
    words = [a for a in args if not a.startswith("-")]
    explicit = any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("--regexp=", "--file=")) for a in args)
    return words[1:] if cmd in PATTERN_FIRST and not explicit else words


def check_secret_reads(cmd, args, reads, ctx):
    strict_words = list(reads)
    if cmd in STRICT_READERS:
        strict_words += positional_args(cmd, args)
    loose_words = []
    if cmd in READERS:
        loose_words += [a for a in args if not a.startswith("-")]
        loose_words += [a.split("=", 1)[1] for a in args if a.startswith("--") and "=" in a]
    where = current_dir(ctx)
    for word, strict in [(w, True) for w in strict_words] + [(w, False) for w in loose_words]:
        reason = secret_reason(word, where, ctx["root"], ctx["vars"], strict)
        if reason:
            ctx["verdict"].add("secret-read", "reading a secret file: " + reason)


def skip_wrapper_options(wrapper, words):
    i, takes_arg = 0, WRAPPER_ARG_OPTS.get(wrapper, set())
    while i < len(words):
        w = words[i]
        if wrapper == "timeout" and re.match(r"^\d", w):
            i += 1
        elif wrapper == "env" and ASSIGN.match(w):
            i += 1
        elif w.startswith("-") and len(w) > 1:
            i += 2 if w in takes_arg else 1
        else:
            break
    return words[i:]


def analyse_segment(words, reads, ctx, depth):
    while words and ASSIGN.match(words[0]):
        name, value = ASSIGN.match(words[0]).groups()
        if BYPASS_ENV.get(name) == value:
            ctx["verdict"].add("git-hook-bypass", "%s=%s disables the git hooks" % (name, value))
        ctx["vars"][name] = value
        words = words[1:]
    while words and words[0] in KEYWORDS:
        words = words[1:]
    if not words:
        return
    cmd, args = os.path.basename(words[0]), words[1:]
    if cmd in WRAPPERS:
        analyse_segment(skip_wrapper_options(cmd, args), reads, ctx, depth)
        return
    if cmd in SHELLS:
        for idx, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and idx + 1 < len(args):
                analyse_isolated(args[idx + 1], ctx, depth + 1)
                break
    elif cmd == "eval":
        analyse_text(" ".join(args), ctx, depth + 1)
    elif cmd in ("cd", "pushd", "popd"):
        change_directory(cmd, args, ctx)
    elif cmd == "rm":
        check_rm(args, ctx)
    elif cmd == "find":
        check_find(args, ctx)
    elif cmd == "git":
        check_git(args, ctx)
    check_secret_reads(cmd, args, reads, ctx)


def snapshot(ctx):
    return ctx["cwd"], ctx["cwd_known"], dict(ctx["vars"])


def restore(ctx, saved):
    ctx["cwd"], ctx["cwd_known"], ctx["vars"] = saved[0], saved[1], dict(saved[2])


def analyse_isolated(text, ctx, depth):
    """Analyse text that runs in its own subshell: a cd or a variable inside does not leak out."""
    saved = snapshot(ctx)
    analyse_text(text, ctx, depth)
    restore(ctx, saved)


def analyse_text(text, ctx, depth=0):
    if depth > MAX_DEPTH:
        ctx["verdict"].add("too-deep", "command nesting is too deep to check")
        return
    scopes = []
    for event in split_segments(tokenize(text)):
        if event[0] == "push":
            scopes.append(snapshot(ctx))
        elif event[0] == "pop":
            if scopes:
                restore(ctx, scopes.pop())
        else:
            _, words, reads, isolated = event
            saved = snapshot(ctx) if isolated else None
            for word in words + reads:
                if word != "$(...)":
                    for inner in find_substitutions(word):
                        analyse_isolated(inner, ctx, depth + 1)
            analyse_segment(words, reads, ctx, depth)
            if saved:
                restore(ctx, saved)


def check_command(command, cwd=None, root=None):
    """Public entry: list of (rule, reason) for a shell command. Empty list = allowed."""
    cwd = os.path.realpath(cwd or os.getcwd())
    ctx = {"verdict": Verdict(), "cwd": cwd, "cwd_known": True, "root": os.path.realpath(root or cwd), "vars": {}}
    if len(command) > MAX_COMMAND_CHARS:
        ctx["verdict"].add("too-long", "command is too long to check")
    else:
        analyse_text(command, ctx)
    return ctx["verdict"].findings


def check_path(path, cwd=None, root=None):
    cwd = os.path.realpath(cwd or os.getcwd())
    reason = secret_reason(path, cwd, os.path.realpath(root or cwd), {})
    return [("secret-read", "touching a secret file: " + reason)] if reason else []


def check_tool_call(payload):
    tool = payload.get("tool_name", "")
    data = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    root = project_root(payload.get("cwd"))
    if tool == "Bash":
        return check_command(str(data.get("command", "")), cwd, root)
    path = data.get("file_path") or data.get("notebook_path") or data.get("path")
    if tool in ("Read", "Edit", "MultiEdit", "Write", "NotebookEdit", "Grep") and path:
        return check_path(str(path), cwd, root)
    return []


# ---------------------------------------------------------------- log, install, main
def log_denial(payload, findings):
    root = project_root(payload.get("cwd"))
    path = os.environ.get("GUARD_LOG") or os.path.join(root, ".claude", LOG_NAME)
    data = payload.get("tool_input") or {}
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": payload.get("tool_name"),
             "rules": [f[0] for f in findings], "reasons": [f[1] for f in findings],
             "input": str(data.get("command") or data.get("file_path") or data.get("path") or "")[:200]}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError as exc:
        sys.stderr.write("guardrails-lite: could not write the denial log (%s)\n" % exc)


def hook_main():
    try:
        payload = json.loads(sys.stdin.read())
        findings = check_tool_call(payload)
    except Exception as exc:  # fail closed: a crash must never become a silent allow
        sys.stderr.write("Blocked by Night Shift Guardrails Lite: internal error, failing closed (%s)\n" % exc)
        return 2
    if not findings:
        return 0
    log_denial(payload, findings)
    for rule, reason in findings:
        sys.stderr.write("Blocked by Night Shift Guardrails Lite [%s]: %s. "
                         "Ask the user to run it themselves if it is intended.\n" % (rule, reason))
    return 2


def install(settings_path, script_path, dry_run=False):
    """Merge the hook into a settings.json file. Returns a message; raises ValueError on invalid JSON."""
    data = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except ValueError as exc:
            raise ValueError("%s is not valid JSON, nothing changed (%s)" % (settings_path, exc))
    entries = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    marker = "night-shift-guardrails-lite/guard.py"
    if any(marker in h.get("command", "") for e in entries for h in e.get("hooks", [])):
        return "already installed in %s" % settings_path
    entries.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": 'python3 "%s"' % script_path}]})
    if dry_run:
        return json.dumps(data, indent=2)
    os.makedirs(os.path.dirname(os.path.abspath(settings_path)), exist_ok=True)
    if os.path.exists(settings_path):
        with open(settings_path, encoding="utf-8") as src:
            backup = src.read()
        with open(settings_path + ".bak-guardrails-lite", "w", encoding="utf-8") as dst:
            dst.write(backup)
    with open(settings_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    return "installed in %s" % settings_path


def cli(argv):
    parser = argparse.ArgumentParser(description="Night Shift Guardrails Lite")
    parser.add_argument("--check", metavar="COMMAND", help="dry run: print the verdict for a shell command")
    parser.add_argument("--install", action="store_true", help="add the hook to a settings.json file")
    parser.add_argument("--settings", help="settings file for --install (default: ./.claude/settings.json)")
    parser.add_argument("--dry-run", action="store_true", help="with --install: print the result, write nothing")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    if args.check is not None:
        findings = check_command(args.check, os.getcwd(), project_root(None))
        for rule, reason in findings:
            print("BLOCK [%s] %s" % (rule, reason))
        if not findings:
            print("ALLOW")
        return 2 if findings else 0
    if args.install:
        settings = args.settings or os.path.join(os.getcwd(), ".claude", "settings.json")
        try:
            print(install(settings, os.path.abspath(__file__), args.dry_run))
        except ValueError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        return 0
    return hook_main()


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
