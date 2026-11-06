"""Bounded, offline integration with this release's adjacent packaging source.

Only the extracted manager's help branch is executed. The actual doctor CLI is
run in --offline mode inside an isolated Python subprocess with audit hooks
which prohibit network access, nested subprocesses and production UNUNKNOWNTUN paths.
All generated fixtures live in a TemporaryDirectory and are removed afterwards.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
# The GitHub handoff places ui/ beside packaging/. Never silently fall back to a
# historical release: compatibility evidence must use the shipped manager.
SOURCE = HERE.parent / "packaging"
SPEC = importlib.util.spec_from_file_location("ununknowntun_ui_compatibility", HERE / "ununknowntun-ui.py")
ui = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ui
SPEC.loader.exec_module(ui)

# The child runs the real script's __main__ entry point and real argparse
# options. Unlike an ordinary --offline call, accidental regressions attempting
# DNS, socket creation or a nested core/service command fail immediately.
AUDITED_DOCTOR = r'''
import os, runpy, socket, ssl, subprocess, sys
def offline_guard(event, args):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.posix_spawn", "os.spawn", "pty.spawn"
    }:
        raise AssertionError("Offline integration forbids network and subprocess calls: " + event)
    if event == "open" and args and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if path.startswith(("/etc/ununknowntun", "/opt/ununknowntun", "/usr/local/bin/ununknowntun", "/var/lib/ununknowntun")):
            raise AssertionError("Offline integration forbids production UNUNKNOWNTUN files")
sys.addaudithook(offline_guard)
doctor_path, fixture_path = sys.argv[1:]
sys.argv = [doctor_path, "--config-dir", fixture_path, "--offline", "--timeout", "1",
            "--binary", os.path.join(fixture_path, "never-execute-core")]
runpy.run_path(doctor_path, run_name="__main__")
'''


class CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (SOURCE / "full-installer.template.sh").is_file() or not (SOURCE / "tunnel-doctor.py").is_file():
            raise unittest.SkipTest("Adjacent release packaging source is required for compatibility integration")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ununknowntun-ui-compat-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = self.root / "compat-fixture"
        self.fixture.mkdir()
        self.token = "private-fixture-token-not-for-display"
        self.ws_path = "/confidential-fixture-websocket-path"
        self.env = (
            "ROLE=origin\nTUNNEL_NAME='Compatibility fixture'\nFOREIGN_DOMAIN=edge.example\n"
            "FOREIGN_PORTS=443\nFOREIGN_PROXY_PROVIDER=none\nIRAN_PROXY_PROVIDER=none\n"
            "IRAN_ENTRY_PORTS=2055\nTARGET_PORT=18082\n"
        )
        self.launcher = (
            "#!/bin/bash\nexec /do/not/execute/ununknowntun \\\n"
            "  -mode origin \\\n  -connect 192.0.2.10:443 \\\n"
            "  -transport wss \\\n  -sni edge.example \\\n  -ws-host edge.example \\\n"
            "  -ws-path " + self.ws_path + " \\\n"
            "  -token-file " + str(self.fixture / "token") + " \\\n"
            "  -ech-mode off \\\n  -tls-fragment off \\\n  -mux on\n"
        )
        self.save()

    def save(self):
        (self.fixture / "deployment.env").write_text(self.env, encoding="utf-8")
        (self.fixture / "run.sh").write_text(self.launcher, encoding="utf-8")
        (self.fixture / "token").write_text(self.token, encoding="utf-8")

    def help_command(self):
        source = (SOURCE / "full-installer.template.sh").read_text(encoding="utf-8")
        start = 'cat > "$CTL_PATH" <<\'CTL\'\n'
        self.assertEqual(source.count(start), 1)
        manager = source.split(start, 1)[1].split("\nCTL\n", 1)[0]
        script = self.root / "manager-help-only.sh"
        script.write_text(manager, encoding="utf-8")
        # Only cat is available to the help branch. All other external commands
        # are unavailable on PATH; bash is selected with an absolute filename.
        binaries = self.root / "help-only-bin"
        binaries.mkdir()
        cat = shutil.which("cat")
        bash = shutil.which("bash")
        self.assertIsNotNone(cat)
        self.assertIsNotNone(bash)
        (binaries / "cat").symlink_to(cat)
        reply = subprocess.run([bash, "--noprofile", "--norc", "-x", str(script), "help"],
                               capture_output=True, text=True, timeout=5, cwd=self.root,
                               env={"PATH": str(binaries), "LC_ALL": "C"})
        self.assertEqual(reply.returncode, 0, reply.stderr)
        self.assertIn("Usage: ununknowntunctl COMMAND", reply.stdout)
        self.assertIn("+ command_name=help", reply.stderr)
        self.assertNotRegex(reply.stderr, r"(?m)^\+ (?:need_root|systemctl|journalctl|curl|wget|python3|source|install|rm|mkdir|chmod)\b")
        return reply

    def test_actual_manager_help_advertises_every_ui_action(self):
        reply = self.help_command()
        supported = set()
        for line in reply.stdout[:ui.LIMIT].splitlines():
            match = re.match(r"^  ([a-z][a-z-]*(?:\|[a-z][a-z-]*)*)(?:\s|$)", line)
            if match:
                supported.update(match[1].split("|"))
        self.assertTrue(ui.ACTIONS <= supported, "Unadvertised UI commands: " + repr(ui.ACTIONS - supported))
        self.assertTrue({"start", "stop", "restart"} <= supported)
        self.assertNotIn("install", supported)

    def test_backend_accepts_real_manager_help_without_running_mutations(self):
        reply = self.help_command()
        selected = ui.inspect_tunnel(self.fixture, check_trust=False)
        backend = ui.Backend()
        for action in sorted(ui.ACTIONS):
            with self.subTest(action=action), mock.patch.object(ui, "inspect_tunnel", return_value=selected), \
                    mock.patch.object(ui, "trusted"), mock.patch.object(ui.subprocess, "run", side_effect=[reply, SimpleNamespace(returncode=0)]) as run:
                self.assertEqual(backend.action(selected, action), 0)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0], [str(ui.MANAGER), action, selected.id])
                self.assertFalse(run.call_args.kwargs.get("shell", False))

    def actual_offline_report(self):
        reply = subprocess.run([sys.executable, "-I", "-c", AUDITED_DOCTOR, str(SOURCE / "tunnel-doctor.py"), str(self.fixture)],
                               capture_output=True, text=True, timeout=8, cwd=self.root,
                               env={"PATH": str(self.root / "no-external-commands"), "LC_ALL": "C"})
        self.assertEqual(reply.returncode, 0, reply.stderr)
        self.assertEqual(reply.stderr, "")
        return json.loads(reply.stdout)

    def test_real_offline_doctor_schema_is_accepted_and_rendered_honestly(self):
        report = self.actual_offline_report()
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["tunnel_id"], self.fixture.name)
        self.assertEqual(report["verdict"], "configuration-checked-not-network-tested")
        self.assertEqual(report["scope"], "offline configuration checks")
        self.assertFalse(report["target_payload_tested"])
        self.assertFalse(report["cdn_origin_policy_verified"])
        self.assertEqual(report["endpoints"], [])
        self.assertIs(ui.validate_report(report), report)
        selected = ui.inspect_tunnel(self.fixture, check_trust=False)
        screen = ui.render([selected], page="doctor", report=report, width=112)
        self.assertIn("configuration-checked-not-network-tested", screen)
        self.assertIn("Network / authentication", screen)
        self.assertIn("Not tested by this report", screen)
        self.assertIn("TODO   Real client payload", screen)
        for secret in (self.token, self.ws_path, str(self.fixture)):
            self.assertNotIn(secret, json.dumps(report) + screen)

    def test_backend_accepts_actual_offline_report_with_matching_id(self):
        report = self.actual_offline_report()
        selected = ui.inspect_tunnel(self.fixture, check_trust=False)
        reply = SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")
        with mock.patch.object(ui, "inspect_tunnel", return_value=selected), mock.patch.object(ui, "trusted"), \
                mock.patch.object(ui.subprocess, "run", return_value=reply) as run:
            result = ui.Backend().doctor(selected, offline=True)
        self.assertEqual(result, report)
        self.assertIn("--offline", run.call_args.args[0])

    def test_signature_detects_undisplayed_connect_secret_path_and_token_changes(self):
        original_env, original_launcher, original_token = self.env, self.launcher, self.token
        original = ui.inspect_tunnel(self.fixture, check_trust=False)
        changes = {
            "connect": lambda: setattr(self, "launcher", original_launcher.replace("192.0.2.10:443", "192.0.2.11:443")),
            "websocket_path": lambda: setattr(self, "launcher", original_launcher.replace(self.ws_path, "/rotated-confidential-path")),
            "token_path": lambda: setattr(self, "launcher", original_launcher.replace(str(self.fixture / "token"), str(self.fixture / "rotated-token"))),
            "token_value": lambda: setattr(self, "token", "rotated-private-fixture-token"),
            "private_metadata": lambda: setattr(self, "env", original_env + "PRIVATE_KEY_PATH=/confidential/private-key.pem\n"),
        }
        for label, change in changes.items():
            with self.subTest(label=label):
                self.env, self.launcher, self.token = original_env, original_launcher, original_token
                change()
                self.save()
                current = ui.inspect_tunnel(self.fixture, check_trust=False)
                self.assertEqual(current.env, original.env)
                if label == "connect":
                    self.assertNotEqual(current.flags["connect"], original.flags["connect"])
                    self.assertEqual({k: v for k, v in current.flags.items() if k != "connect"},
                                     {k: v for k, v in original.flags.items() if k != "connect"})
                else:
                    self.assertEqual(current.flags, original.flags)
                self.assertNotEqual(current.signature, original.signature)
                with mock.patch.object(ui, "inspect_tunnel", return_value=current), \
                        mock.patch.object(ui.subprocess, "run", side_effect=AssertionError("No command allowed")), self.assertRaises(ui.UIError):
                    ui.Backend().check_selected(original)
                rendered = repr(current) + "".join(ui.render([current], page=page) for page in ("tunnels", "tuning", "doctor"))
                for hidden in (original_token, self.token, self.ws_path, "/rotated-confidential-path", str(self.fixture),
                               "/confidential/private-key.pem", current.signature):
                    self.assertNotIn(hidden, rendered)

    def test_installed_but_unloaded_service_is_visible_and_readonly(self):
        registry = mock.Mock()
        registry.exists.return_value = False
        loaded = SimpleNamespace(returncode=0, stdout="ununknowntun.service loaded active running existing\n", stderr="")
        installed = SimpleNamespace(returncode=0, stdout="ununknowntun.service enabled\nununknowntun35-unloaded.service disabled\nununknowntun@.service disabled\n", stderr="")
        with mock.patch.object(ui, "REGISTRY", registry), mock.patch.object(ui.subprocess, "run", side_effect=[loaded, installed]) as run:
            actual = ui.Backend().inventory()
        self.assertEqual(run.call_count, 2)
        entries = {entry.id: entry for entry in actual}
        self.assertEqual(set(entries), {"ununknowntun.service", "ununknowntun35-unloaded.service"})
        self.assertEqual(entries["ununknowntun35-unloaded.service"].state, "not-loaded")
        self.assertFalse(entries["ununknowntun35-unloaded.service"].managed)
        self.assertFalse(entries["ununknowntun.service"].managed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
