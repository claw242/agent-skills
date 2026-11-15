"""Tests for guard.py (standard library only). Commands are analysed as strings, never executed."""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "..", "skills", "night-shift-guardrails-lite", "guard.py")
spec = importlib.util.spec_from_file_location("guard", GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

NV = "--no-" + "verify"

BLOCKED = [
    ("rm -rf /", "rm-outside-project"),
    ("rm -rf ~", "rm-outside-project"),
    ("rm -rf ~/Documents", "rm-outside-project"),
    ("rm -rf $HOME/projects", "rm-outside-project"),
    ("rm -rf ${HOME}", "rm-outside-project"),
    ("rm -rf ../other", "rm-outside-project"),
    ("rm -rf .", "rm-outside-project"),
    ("rm -fr /etc", "rm-outside-project"),
    ("rm --recursive --force /var/data", "rm-outside-project"),
    ("sudo rm -rf /usr/local", "rm-outside-project"),
    ("rm -rf $UNKNOWN_DIR", "rm-outside-project"),
    ("rm -rf /tmp/scratch", "rm-outside-project"),
    ('r"m" -rf /etc', "rm-outside-project"),
    ("ls; rm -rf /etc", "rm-outside-project"),
    ("make build && rm -rf /opt/app", "rm-outside-project"),
    ("echo ok $(rm -rf /etc)", "rm-outside-project"),
    ('echo "x `rm -rf /etc` y"', "rm-outside-project"),
    ('bash -c "rm -rf /etc"', "rm-outside-project"),
    ("eval 'rm -rf /etc'", "rm-outside-project"),
    ("D=/etc; rm -rf $D", "rm-outside-project"),
    ("find / -name '*.log' -delete", "rm-outside-project"),
    ("git push --force", "git-force-push"),
    ("git push -f origin main", "git-force-push"),
    ("git push --force-with-lease origin main", "git-force-push"),
    ("git push origin +main", "git-force-push"),
    ("git -C sub push -uf origin main", "git-force-push"),
    ("true && git push --force", "git-force-push"),
    ("git commit -m x " + NV, "git-hook-bypass"),
    ("git push " + NV, "git-hook-bypass"),
    ("git commit -nm 'x'", "git-hook-bypass"),
    ("git -c core.hooksPath=/dev/null commit -m x", "git-hook-bypass"),
    ("HUSKY=0 git commit -m x", "git-hook-bypass"),
    ("cat .env", "secret-read"),
    ("cat .env.production", "secret-read"),
    ("cat < .env", "secret-read"),
    ("grep KEY ./config/.env.local", "secret-read"),
    ("head -n 3 ~/.ssh/id_rsa", "secret-read"),
    ("cat ~/.aws/credentials", "secret-read"),
    ("cp server.pem /tmp/x", "secret-read"),
    ("source .env", "secret-read"),
    ("cat .env*", "secret-read"),
    ("export $(cat .env)", "secret-read"),
    ("cd .. && rm -rf neighbour", "rm-outside-project"),
    ("cd /etc && rm -rf foo", "rm-outside-project"),
    ("cd ~ && rm -rf work", "rm-outside-project"),
    ("pushd .. && rm -rf neighbour", "rm-outside-project"),
    ("cd - && rm -rf build", "rm-outside-project"),
    ("cd $UNSET_DIR_Q && rm -rf build", "rm-outside-project"),
    ("cd sub; cd ../..; rm -rf x", "rm-outside-project"),
    ("cat $UNSET_NAME_Q", "secret-read"),
    ('cat < "$UNSET_NAME_Q"', "secret-read"),
    ("SF=.env; cat $SF", "secret-read"),
    ("cd sub && cat ../.env", "secret-read"),
    ('cd .. && rm -rf "$PWD/neighbour"', "rm-outside-project"),
    ("cd .. && rm -rf ${PWD}/neighbour", "rm-outside-project"),
    ("cd $UNSET_DIR_Q; rm -rf $PWD/x", "rm-outside-project"),
    ("(cd .. && rm -rf neighbour)", "rm-outside-project"),
    ("(cd ..); (cd ..; rm -rf neighbour)", "rm-outside-project"),
    ('bash -c "cd .. && rm -rf neighbour"', "rm-outside-project"),
    ('echo "$(cd .. && rm -rf neighbour)"', "rm-outside-project"),
    ('cd .. && echo "$(rm -rf neighbour)"', "rm-outside-project"),
    ("echo $(cd ..; rm -rf neighbour)", "rm-outside-project"),
    ("cd sub | cat; cd .. ; rm -rf ../x", "rm-outside-project"),
    ("cat $(echo a) .env", "secret-read"),
    ("{ cd ..; rm -rf neighbour; }", "rm-outside-project"),
    ("cd ..; echo `rm -rf neighbour`", "rm-outside-project"),
    ("if true; then rm -rf /etc; fi", "rm-outside-project"),
]

ALLOWED = [
    "ls -la",
    "rm -rf node_modules",
    "rm -rf ./build/cache",
    "rm file.txt",
    "rm -f ~/not-recursive.txt",
    "git push origin main",
    "git push -u origin feature",
    "git push --dry-run",
    "git push -n origin main",
    "git commit -m 'fix: tidy up'",
    "git commit -am 'feat: add thing'",
    "git status && git diff",
    "cat README.md",
    "cat .env.example",
    "cat ~/.ssh/id_rsa.pub",
    "grep -rn TODO src/",
    "echo 'rm -rf / is dangerous' > notes.txt",
    "python3 -m unittest",
    "cd sub && rm -rf build",
    "cd sub; cd ..; rm -rf build",
    "(cd .. && ls); rm -rf build",
    "(cd ..) && rm -rf build",
    'bash -c "cd .. && ls"; rm -rf build',
    "cd .. | cat; rm -rf build",
    "cd .. & rm -rf build",
    "echo $(cd ..; pwd); rm -rf build",
    "cd sub && rm -rf $PWD/build",
    "cd /etc && cat hosts",
    'grep -rn "$PATTERN_Q" src/',
    "cat README.md > out.txt",
    "find . -name '*.pyc' -delete",
    "cat <<'EOF' > note.txt\nit's fine, even rm -rf / in a heredoc\nEOF",
    'git commit -m "$(cat <<\'EOF\'\nfeat: it\'s ok\nEOF\n)"',
]


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def rules(self, command):
        return {rule for rule, _ in guard.check_command(command, self.root, self.root)}

    def test_blocked_commands(self):
        for command, rule in BLOCKED:
            with self.subTest(command=command):
                self.assertIn(rule, self.rules(command))

    def test_allowed_commands(self):
        for command in ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(self.rules(command), set())

    def test_symlink_to_secret_is_blocked(self):
        os.symlink(".env", os.path.join(self.root, "config.txt"))
        self.assertIn("secret-read", self.rules("cat config.txt"))
        self.assertTrue(guard.check_path("config.txt", self.root, self.root))
        os.symlink("README.md", os.path.join(self.root, "docs.txt"))
        self.assertEqual(self.rules("cat docs.txt"), set())

    def test_environment_variable_pointing_to_secret(self):
        with mock.patch.dict(os.environ, {"SECRET_FILE_Q": ".env", "PLAIN_FILE_Q": "README.md"}):
            self.assertIn("secret-read", self.rules('cat "$SECRET_FILE_Q"'))
            self.assertIn("secret-read", self.rules("cat ${SECRET_FILE_Q}"))
            self.assertEqual(self.rules('cat "$PLAIN_FILE_Q"'), set())

    def test_temp_dir_opt_in(self):
        with mock.patch.dict(os.environ, {"GUARD_ALLOW_TEMP": "1"}):
            self.assertEqual(self.rules("rm -rf /tmp/scratch"), set())
            self.assertIn("rm-outside-project", self.rules("rm -rf /etc"))

    def test_unbalanced_quote_still_checked(self):
        self.assertIn("rm-outside-project", self.rules("echo 'oops; rm -rf /etc"))

    def test_too_deep_is_refused(self):
        command = "echo done"
        for _ in range(8):
            command = "bash -c %s" % json.dumps(command)
        self.assertIn("too-deep", self.rules(command))

    def test_path_check_for_tools(self):
        self.assertTrue(guard.check_path(".env", self.root, self.root))
        self.assertTrue(guard.check_path(os.path.join(self.root, "keys", "deploy.pem"), self.root, self.root))
        self.assertEqual(guard.check_path("src/app.py", self.root, self.root), [])
        self.assertEqual(guard.check_path(".env.example", self.root, self.root), [])


class HookProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.env = {k: v for k, v in os.environ.items() if k not in ("GUARD_LOG", "GUARD_ALLOW_TEMP")}
        self.env["CLAUDE_PROJECT_DIR"] = self.root

    def run_hook(self, payload, raw=None):
        data = raw if raw is not None else json.dumps(payload)
        return subprocess.run([sys.executable, "-I", GUARD], input=data, capture_output=True, text=True,
                              env=self.env, cwd=self.root, timeout=30)

    def test_block_exit_code_log_and_message(self):
        done = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "git push --force"}, "cwd": self.root})
        self.assertEqual(done.returncode, 2)
        self.assertIn("git-force-push", done.stderr)
        log = os.path.join(self.root, ".claude", "guardrails-denials.jsonl")
        with open(log, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh]
        self.assertEqual(entries[0]["rules"], ["git-force-push"])
        self.assertEqual(entries[0]["tool"], "Bash")

    def test_allow_exit_code_and_no_log(self):
        done = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": self.root})
        self.assertEqual(done.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".claude", "guardrails-denials.jsonl")))

    def test_read_tool_on_secret_is_blocked(self):
        payload = {"tool_name": "Read", "tool_input": {"file_path": os.path.join(self.root, ".env")}, "cwd": self.root}
        self.assertEqual(self.run_hook(payload).returncode, 2)

    def test_unrelated_tool_is_allowed(self):
        self.assertEqual(self.run_hook({"tool_name": "WebFetch", "tool_input": {"url": "https://x.test"}}).returncode, 0)

    def test_invalid_json_fails_closed(self):
        self.assertEqual(self.run_hook(None, raw="not json").returncode, 2)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = os.path.join(self.tmp.name, ".claude", "settings.json")
        self.script = "/x/skills/night-shift-guardrails-lite/guard.py"

    def test_install_creates_file_and_is_idempotent(self):
        self.assertIn("installed", guard.install(self.settings, self.script))
        self.assertIn("already installed", guard.install(self.settings, self.script))
        with open(self.settings, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 1)
        self.assertIn(self.script, data["hooks"]["PreToolUse"][0]["hooks"][0]["command"])

    def test_install_keeps_existing_settings_and_makes_backup(self):
        os.makedirs(os.path.dirname(self.settings))
        with open(self.settings, "w", encoding="utf-8") as fh:
            json.dump({"permissions": {"allow": ["Bash(ls)"]}}, fh)
        guard.install(self.settings, self.script)
        with open(self.settings, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["permissions"]["allow"], ["Bash(ls)"])
        self.assertTrue(os.path.exists(self.settings + ".bak-guardrails-lite"))

    def test_invalid_settings_are_not_touched(self):
        os.makedirs(os.path.dirname(self.settings))
        with open(self.settings, "w", encoding="utf-8") as fh:
            fh.write("{broken")
        with self.assertRaises(ValueError):
            guard.install(self.settings, self.script)
        with open(self.settings, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{broken")

    def test_dry_run_writes_nothing(self):
        out = guard.install(self.settings, self.script, dry_run=True)
        self.assertIn("PreToolUse", out)
        self.assertFalse(os.path.exists(self.settings))

    def test_cli_check_prints_verdict(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            code = guard.cli(["--check", "git push --force"])
        self.assertEqual(code, 2)
        self.assertIn("BLOCK [git-force-push]", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
