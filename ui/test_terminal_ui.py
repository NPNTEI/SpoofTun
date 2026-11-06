"""Offline safety and rendering tests. Never runs server or service commands."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("ununknowntun-ui.py")
SPEC = importlib.util.spec_from_file_location("ununknowntun_terminal_ui_under_test", MODULE_PATH)
ui = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ui
SPEC.loader.exec_module(ui)


def tunnel(identifier="turkey-yta", **kwargs):
    values = dict(id=identifier, name="Turkey YTA", unit="ununknowntun@" + identifier + ".service",
                  role="origin", env={"ROLE": "origin", "FOREIGN_DOMAIN": "edge.example"},
                  flags={"transport": "wss", "mux": "on"})
    values.update(kwargs)
    return ui.Tunnel(**values)


class OfflineCase(unittest.TestCase):
    def enterContext(self, context):
        """Python 3.8-compatible equivalent of TestCase.enterContext."""
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def setUp(self):
        self.process = self.enterContext(mock.patch.object(
            ui.subprocess, "run", side_effect=AssertionError("Unexpected system command in offline test")))
        self.stdout = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def make_app(self, replies=(), demo=False, tunnels=None):
        backend = mock.Mock(spec=ui.Backend)
        backend.notice = ""
        backend.inventory.return_value = [tunnel()] if tunnels is None else tunnels
        backend.action.return_value = 0
        backend.doctor.return_value = {"verdict": "configuration-checked-not-network-tested", "checks": [], "endpoints": []}
        app = ui.App(demo=demo, color=False, backend=backend, input_fn=mock.Mock(side_effect=list(replies)))
        app.refresh()
        return app, backend


class ParserTests(OfflineCase):
    def test_ids_restrict_command_and_path_injection(self):
        for good in ("a", "turkey-yta", "n0", "a" * 48):
            with self.subTest(good=good):
                self.assertTrue(ui.valid_id(good))
        for bad in ("", "../other", "a/b", "--help", "a--b", "A", "name;id", "x\n", "a" * 49):
            with self.subTest(bad=bad):
                self.assertFalse(ui.valid_id(bad))

    def test_env_parses_literal_quotes_and_ignores_secrets(self):
        result = ui.parse_env("# deployment\nROLE=origin\nTUNNEL_NAME='Turkey YTA'\nFOREIGN_DOMAIN=edge.example\nTOKEN=never-display\n")
        self.assertEqual(result, {"ROLE": "origin", "TUNNEL_NAME": "Turkey YTA", "FOREIGN_DOMAIN": "edge.example"})
        self.assertNotIn("never-display", str(result))

    def test_env_never_evaluates_bash_ansi_display_name(self):
        result = ui.parse_env("ROLE=egress\nTUNNEL_NAME=$'evil\\nname'\n")
        self.assertEqual(result["TUNNEL_NAME"], "")
        self.process.assert_not_called()

    def test_env_rejects_malformed_duplicate_dynamic_and_invalid_role(self):
        invalid = ("", "ROLE=unknown", "ROLE=origin\nROLE=egress", "ROLE=origin\nTOKEN=x\nTOKEN=y",
                   "source /tmp/no", "export ROLE=origin", "ROLE=origin\nFOREIGN_DOMAIN=$(id)",
                   "ROLE=origin\nFOREIGN_DOMAIN=`id`", "ROLE=origin\nTUNNEL_NAME='unterminated",
                   "ROLE=origin\nFOREIGN_DOMAIN=two words", "ROLE=origin\nTUNNEL_NAME=a\tb")
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ui.UIError):
                ui.parse_env(text)
        self.process.assert_not_called()

    def test_flags_retains_only_safe_display_fields(self):
        result = ui.parse_flags("#!/bin/bash\nexec /usr/local/bin/ununknowntun \\\n  -transport wss \\\n  -mux on \\\n  -token-file /private/secret \\\n  -sessions 8 \\\n  -tls-fragment\n")
        self.assertEqual(result, {"transport": "wss", "mux": "on", "sessions": "8", "tls-fragment": "true"})
        self.assertNotIn("secret", str(result))

    def test_new_flags_show_endpoints_and_modes_but_hide_ech_descriptor(self):
        flags = ui.parse_flags("  -connect 192.0.2.10:443\n  -sni edge.example\n  -ws-host route.example\n  -ech-config 'ech.example+https://resolver.example/dns-query?key=private-query'\n  -xhttp-mode stream-up\n  -padding-bytes 10-40\n  -xhttp-padding-bytes 100-1000\n")
        self.assertEqual(flags["connect"], "192.0.2.10:443")
        self.assertEqual(flags["sni"], "edge.example")
        self.assertEqual(flags["ws-host"], "route.example")
        self.assertEqual(flags["xhttp-mode"], "stream-up")
        self.assertEqual(flags["padding-bytes"], "10-40")
        self.assertEqual(flags["xhttp-padding-bytes"], "100-1000")
        self.assertEqual(flags["ech-config"], "Manual DNS descriptor (resolver hidden)")
        self.assertNotIn("private-query", repr(flags))
        self.assertNotIn("resolver.example", repr(flags))

    def test_ech_source_categories_never_display_raw_config_or_path(self):
        for source, expected in (("auto", "Automatic DNS discovery"), ("base64:ABCprivateBYTES", "Manual ECHConfigList (value hidden)"), ("ABCprivateBYTES==", "Manual ECHConfigList (value hidden)"), ("/private/ech/config", "Manual source (not validated; value hidden)")):
            with self.subTest(source=source):
                self.assertEqual(ui.ech_source_label(source), expected)

    def test_endpoint_labels_hide_url_credentials_and_preserve_ipv6(self):
        self.assertEqual(ui.endpoint_label("[2001:db8::1]:443,edge.example:8443"), "[2001:db8::1]:443,edge.example:8443")
        for source in ("https://user:password@edge.example/query?secret=x", "edge.example/path", "edge.example\x1b[2J", "$(id)"):
            self.assertEqual(ui.endpoint_label(source), "invalid endpoint (details hidden)")

    def test_flags_rejects_duplicate_dynamic_and_shell_layout(self):
        invalid = ("  -transport wss\n  -transport xhttp", "  -sessions $(id)", "  -mux `id`",
                   "  -mux on ; id", "  -mux 'unfinished", "  -token-file x\n  -token-file y")
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ui.UIError):
                ui.parse_flags(text)
        self.process.assert_not_called()

    def test_child_environment_removes_injection_vars(self):
        values = {"PATH": "/attacker", "BASH_ENV": "x", "ENV": "x", "LD_PRELOAD": "x",
                  "DYLD_INSERT_LIBRARIES": "x", "PYTHONPATH": "x", "PYTHONINSPECT": "1",
                  "BASH_FUNC_x%%": "() { :; }", "UNUNKNOWNTUN_TOKEN": "secret", "V7_TOKEN": "secret",
                  "SHELLOPTS": "x", "BASHOPTS": "x", "SAFE_SETTING": "keep"}
        with mock.patch.dict(os.environ, values, clear=True):
            env = ui.child_env()
        self.assertEqual(env["PATH"], ui.SAFE_PATH)
        self.assertEqual(env["SAFE_SETTING"], "keep")
        self.assertEqual(env["SYSTEMD_PAGER"], "cat")
        self.assertEqual(env["PAGER"], "cat")
        for key in values:
            if key not in ("PATH", "SAFE_SETTING"):
                self.assertNotIn(key, env)

    def test_sanitizer_removes_terminal_bidi_controls_and_bounds_text(self):
        result = ui.clean("hello\x1b]52;c;bad\x07\n\r\t\x00\u202e\u2066world")
        self.assertFalse(any(ui.unicodedata.category(c).startswith("C") for c in result))
        self.assertEqual(len(ui.clean("x" * 4096)), 2048)

    def test_fit_uses_display_cells(self):
        for text in ("ASCII", "界界界界界", "e\u0301" * 10, "abc界e\u0301xyz", "\x1b[31mbad"):
            for width in range(0, 15):
                with self.subTest(text=text, width=width):
                    self.assertLessEqual(ui.cells(ui.fit(text, width)), width)
        self.assertEqual(ui.cells("界e\u0301"), 3)

    def test_small_read_size_encoding_and_inspection_are_data_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example"
            path.mkdir()
            (path / "deployment.env").write_text("ROLE=origin\nTUNNEL_NAME='Example node'\n", encoding="utf-8")
            (path / "run.sh").write_text("  -transport wss\n", encoding="utf-8")
            actual = ui.inspect_tunnel(path, check_trust=False)
            self.assertEqual((actual.id, actual.name, actual.flags), ("example", "Example node", {"transport": "wss"}))
            probe = path / "data"
            probe.write_bytes(b"\xff")
            with self.assertRaises(ui.UIError):
                ui.read_small(probe, check_trust=False)
            probe.write_bytes(b"a" * (ui.LIMIT + 1))
            with self.assertRaises(ui.UIError):
                ui.read_small(probe, check_trust=False)
        self.process.assert_not_called()

    def test_inspection_rejects_symlink_and_invalid_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            link = Path(directory) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ui.UIError):
                ui.inspect_tunnel(link, check_trust=False)
            with self.assertRaises(ui.UIError):
                ui.inspect_tunnel(Path(directory) / "INVALID", check_trust=False)

    def test_cdn_settings_change_invalidates_selection_signature_without_display(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example"
            path.mkdir()
            (path / "deployment.env").write_text("ROLE=origin\nCONNECT_HOST=192.0.2.10\n")
            (path / "run.sh").write_text("  -transport wss\n")
            settings = path / "cdn-endpoints.json"
            settings.write_text('{"enabled":false,"private":"not-display"}')
            first = ui.inspect_tunnel(path, check_trust=False)
            settings.write_text('{"enabled":true,"private":"not-display"}')
            second = ui.inspect_tunnel(path, check_trust=False)
            self.assertEqual(first.flags, second.flags)
            self.assertNotEqual(first.signature, second.signature)
            self.assertNotIn("not-display", repr(second))
            with mock.patch.object(ui, "inspect_tunnel", return_value=second), self.assertRaises(ui.UIError):
                ui.Backend().check_selected(first)

    def test_trust_refuses_bad_ownership_permissions_symlinks_and_directory(self):
        cases = ((stat.S_IFREG | 0o644, 1000), (stat.S_IFREG | 0o666, 0),
                 (stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o755, 0))
        for mode, uid in cases:
            info = SimpleNamespace(st_mode=mode, st_uid=uid)
            with self.subTest(mode=mode, uid=uid), mock.patch.object(Path, "lstat", return_value=info), \
                    mock.patch.object(Path, "stat", return_value=info), self.assertRaises(ui.UIError):
                ui.trusted(Path("/test/managed"))


class RenderTests(OfflineCase):
    def test_tuning_exposes_separate_endpoints_padding_and_truthful_limits(self):
        selected = tunnel(env={"CONNECT_HOST": "192.0.2.10", "FOREIGN_DOMAIN": "origin.example", "FOREIGN_PROXY_PROVIDER": "cloudflare"}, flags=ui.parse_flags("  -connect 192.0.2.10:443\n  -sni tls.example\n  -ws-host http.example\n  -transport xhttp\n  -xhttp-mode stream-one\n  -padding-bytes 10-40\n  -xhttp-padding-bytes 100-1000\n  -ech-config 'ech.example+https://resolver.example/private?secret=x'\n"))
        screen = ui.render([selected], page="tuning", width=112)
        for value in ("Dial endpoint", "192.0.2.10:443", "TLS SNI", "tls.example", "HTTP Host", "http.example", "Frame padding bytes", "10-40", "XHTTP HTTP padding", "100-1000", "stream-one", "Path rotation", "Carrier renewal", "Preview scan", "TLS modes"):
            self.assertIn(value, screen)
        self.assertNotIn("mode 4", screen)
        self.assertNotIn("secret=x", screen)
        self.assertNotIn("resolver.example", screen)
        self.assertNotIn("PASS", screen)

    def test_all_pages_fit_requested_display_width(self):
        rows = ui.demo_tunnels()
        rows[0].name = "界e\u0301" * 160 + "\x1b[2J\u202eevil"
        report = {"verdict": "failed", "checks": [{"status": "pass", "stage": "配置" * 50}],
                  "endpoints": [{"leg": "edge", "checks": [{"status": "fail", "stage": "TLS", "error": "long error " * 50}]}]}
        for width in (32, 48, 60, 94, 112):
            for page in ("tunnels", "tuning", "doctor"):
                for ascii_only in (False, True):
                    for color in (False, True):
                        with self.subTest(width=width, page=page, ascii=ascii_only, color=color):
                            result = ui.render(rows, page=page, report=report, width=width, color=color, ascii_only=ascii_only)
                            for line in result.splitlines():
                                line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                                self.assertEqual(ui.cells(line), width)
                                self.assertNotIn("\x1b", line)
                                self.assertNotIn("\u202e", line)
                                if ascii_only:
                                    self.assertTrue(line.isascii())

    def test_doctor_reports_exact_endpoint_and_error_detail(self):
        report = {"verdict": "failed", "endpoints": [{"endpoint": "edge.example:443", "leg": "foreign",
                  "checks": [{"status": "fail", "stage": "authentication", "detail": "context deadline exceeded",
                              "next_step": "Check the configured peer"}]}]}
        rows = ui.diagnostic_rows(report)
        self.assertEqual(rows[0][0], "FAIL")
        self.assertEqual(rows[0][1], "edge.example:443 / authentication")
        self.assertIn("context deadline exceeded", rows[0][2])
        self.assertIn("Check the configured peer", rows[0][2])

    def test_empty_and_unmanaged_views_never_claim_verified_health(self):
        empty = ui.render([], page="doctor")
        self.assertIn("No tunnels found", empty)
        self.assertNotIn("PASS", empty)
        unmanaged = ui.render([tunnel(managed=False)], page="tuning")
        self.assertIn("READ ONLY", unmanaged)
        self.assertIn("Editing is unavailable", unmanaged)

    def test_unrun_diagnostics_are_waiting_and_real_client_is_always_todo(self):
        rows = ui.diagnostic_rows(None)
        self.assertNotIn("PASS", [row[0] for row in rows])
        for report in (None, {"verdict": "carrier-authenticated", "checks": [{"stage": "TLS", "status": "pass"}], "endpoints": []}):
            rows = ui.diagnostic_rows(report)
            self.assertEqual(rows[-1][0:2], ("TODO", "Real client payload"))


class AppTests(OfflineCase):
    def test_icmp_management_is_available_without_standard_tunnels(self):
        app, backend = self.make_app(replies=[""], tunnels=[])
        backend.icmp_manager.return_value = 0
        self.assertTrue(app.dispatch("i"))
        backend.icmp_manager.assert_called_once_with()
        backend.action.assert_not_called()

    def test_demo_blocks_icmp_management_and_all_pages_advertise_it(self):
        app, backend = self.make_app(demo=True)
        with self.assertRaises(ui.UIError):
            app.dispatch("i")
        backend.icmp_manager.assert_not_called()
        for page in ("tunnels", "tuning", "doctor"):
            self.assertIn("i Direct ICMP manager", ui.render([], page=page))

    def test_demo_never_invokes_any_backend_or_prompts_for_actions(self):
        app, backend = self.make_app(demo=True)
        for command in ("1", "2", "3", "t 2", "r"):
            self.assertTrue(app.dispatch(command))
        for command in ("d", "f", "e", "a", "c", "u", "o", "n", "b", "p", "s", "v"):
            with self.subTest(command=command), self.assertRaises(ui.UIError):
                app.dispatch(command)
        self.assertEqual(backend.mock_calls, [])
        app.input.assert_not_called()
        self.process.assert_not_called()

    def test_invalid_selection_and_unknown_option_keep_selection(self):
        app, backend = self.make_app(tunnels=[tunnel(), tunnel("another")])
        app.dispatch("t 2")
        for command in ("t 0", "t 3", "t 999", "t -1", "t bad", "start all", "../bad", "sudo reboot"):
            with self.subTest(command=command), self.assertRaises(ui.UIError):
                app.dispatch(command)
            self.assertEqual(app.selected, 1)
        backend.action.assert_not_called()

    def test_quit_and_blank_do_not_change_anything(self):
        app, backend = self.make_app()
        self.assertTrue(app.dispatch(""))
        for command in ("q", "0", "exit"):
            self.assertFalse(app.dispatch(command))
        backend.action.assert_not_called()

    def test_mutations_default_cancel_and_require_exact_id(self):
        cases = [("e", [], "edit"), ("a", [], "edit-apply"), ("c", [], "customers"),
                 ("n", [], "cdn"), ("b", [], "cdn-rounds"), ("s", [], "cdn-scan"),
                 ("o", ["1"], "start"), ("o", ["2"], "stop"), ("o", ["3"], "restart"), ("o", ["4"], "delete")]
        for command, prefix, action in cases:
            for reply in ("", "y", "yes", "TURKEY-YTA", "another"):
                with self.subTest(command=command, action=action, reply=reply):
                    app, backend = self.make_app(prefix + [reply])
                    self.assertTrue(app.dispatch(command))
                    backend.action.assert_not_called()
                    self.assertIn("Cancelled", app.notice)
            with self.subTest(action=action, accepted=True):
                app, backend = self.make_app(prefix + ["turkey-yta", ""])
                selected = app.tunnels[0]
                self.assertTrue(app.dispatch(command))
                backend.action.assert_called_once_with(selected, action)

    def test_unknown_service_action_has_no_fallback(self):
        for reply in ("", "5", "all", "delete"):
            app, backend = self.make_app([reply])
            with self.subTest(reply=reply), self.assertRaises(ui.UIError):
                app.dispatch("o")
            backend.action.assert_not_called()

    def test_unmanaged_and_blocked_entries_refuse_all_actions(self):
        for selected in (tunnel(managed=False), tunnel(error="unreadable")):
            for command in ("d", "f", "e", "a", "c", "u", "o", "n", "b", "p", "s", "v"):
                with self.subTest(command=command, managed=selected.managed, error=selected.error):
                    app, backend = self.make_app(tunnels=[selected])
                    with self.assertRaises(ui.UIError):
                        app.dispatch(command)
                    backend.action.assert_not_called()
                    backend.doctor.assert_not_called()
                    app.input.assert_not_called()

    def test_refresh_invalidates_reports_and_preserves_selection_by_id(self):
        first, second = tunnel(), tunnel("second")
        app, backend = self.make_app(tunnels=[first, second])
        app.dispatch("t 2")
        app.reports[second.id] = {"verdict": "carrier-authenticated"}
        backend.inventory.return_value = [second, first]
        app.dispatch("r")
        self.assertEqual(app.selected, 0)
        self.assertEqual(app.tunnels[app.selected].id, second.id)
        self.assertEqual(app.reports, {})

    def test_new_doctor_cancel_and_failure_invalidate_stale_pass(self):
        for response, failure in (("", None), ("n", None), ("y", ui.UIError("timeout"))):
            with self.subTest(response=response):
                app, backend = self.make_app([response])
                app.reports["turkey-yta"] = {"verdict": "carrier-authenticated"}
                if failure:
                    backend.doctor.side_effect = failure
                    with self.assertRaises(ui.UIError):
                        app.dispatch("d")
                else:
                    app.dispatch("d")
                    backend.doctor.assert_not_called()
                self.assertNotIn("turkey-yta", app.reports)
                self.assertEqual(app.page, "doctor")

    def test_doctor_and_offline_dispatch_are_explicit(self):
        for command, responses, offline in (("d", ["y"], False), ("f", [], True)):
            with self.subTest(command=command):
                app, backend = self.make_app(responses)
                selected = app.tunnels[0]
                app.dispatch(command)
                backend.doctor.assert_called_once_with(selected, offline=offline)
                self.assertEqual(app.reports[selected.id], backend.doctor.return_value)

    def test_cdn_status_has_no_mutation_confirmation_and_no_scan(self):
        app, backend = self.make_app([""])
        selected = app.tunnels[0]
        app.dispatch("v")
        backend.action.assert_called_once_with(selected, "cdn-status")
        backend.doctor.assert_not_called()
        app.input.assert_called_once_with("Press Enter to return to the dashboard. ")

    def test_preview_shortcut_delegates_without_applying_or_confirming_mutation(self):
        app, backend = self.make_app([""])
        selected = app.tunnels[0]
        app.dispatch("p")
        backend.action.assert_called_once_with(selected, "cdn-preview")
        backend.doctor.assert_not_called()
        app.input.assert_called_once_with("Press Enter to return to the dashboard. ")

    def test_refresh_and_page_navigation_never_enable_scanning(self):
        app, backend = self.make_app()
        for command in ("1", "2", "3", "r", "t 1"):
            app.dispatch(command)
        backend.action.assert_not_called()
        backend.doctor.assert_not_called()
        app.input.assert_not_called()


class BackendTests(OfflineCase):
    def test_icmp_console_requires_trusted_sibling_and_fixed_interpreter(self):
        self.return_process(code=4)
        with mock.patch.object(ui, "trusted") as trust:
            self.assertEqual(self.backend.icmp_manager(), 4)
        trust.assert_called_once_with(ui.ICMP_CONSOLE)
        self.assertEqual(ui.ICMP_CONSOLE.parent, MODULE_PATH.absolute().parent)
        self.assertEqual(self.process.call_args.args[0], ["/usr/bin/python3", "-I", str(ui.ICMP_CONSOLE)])
        self.assertFalse(self.process.call_args.kwargs.get("shell", False))

    def test_unsafe_icmp_console_does_not_execute(self):
        with mock.patch.object(ui, "trusted", side_effect=ui.UIError("unsafe")), self.assertRaises(ui.UIError):
            self.backend.icmp_manager()
        self.process.assert_not_called()

    def setUp(self):
        super().setUp()
        self.backend = ui.Backend()
        self.selected = tunnel()
        self.registry = Path("/test-only/registry")
        self.enterContext(mock.patch.object(ui, "REGISTRY", self.registry))

    def mock_checks(self):
        self.enterContext(mock.patch.object(ui, "inspect_tunnel", return_value=self.selected))
        return self.enterContext(mock.patch.object(ui, "trusted"))

    def return_process(self, code=0, stdout="", stderr=""):
        self.process.side_effect = None
        self.process.return_value = SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    def test_actions_use_fixed_argv_explicit_id_and_no_shell(self):
        trust = self.mock_checks()
        self.return_process(stdout="\n".join("  " + action + " ID" for action in ui.ACTIONS))
        for action in sorted(ui.ACTIONS):
            with self.subTest(action=action):
                self.process.reset_mock()
                self.assertEqual(self.backend.action(self.selected, action), 0)
                args, kwargs = self.process.call_args
                self.assertEqual(args[0], [str(ui.MANAGER), action, self.selected.id])
                self.assertEqual(self.process.call_count, 2)
                help_args, help_kwargs = self.process.call_args_list[0]
                self.assertEqual(help_args[0], [str(ui.MANAGER), "help"])
                self.assertEqual(help_kwargs["timeout"], 5)
                self.assertFalse(help_kwargs.get("shell", False))
                self.assertFalse(kwargs.get("shell", False))
                self.assertEqual(kwargs["env"]["PATH"], ui.SAFE_PATH)
        self.assertIn(mock.call(ui.MANAGER), trust.call_args_list)
        self.assertIn(mock.call(ui.DOCTOR.with_name("tunnel-editor.py")), trust.call_args_list)
        self.assertIn(mock.call(ui.DOCTOR.with_name("access-manager.py")), trust.call_args_list)

    def test_manager_missing_capability_or_help_failure_blocks_action(self):
        self.mock_checks()
        for code, output in ((0, "  list\n  status ID\n"), (1, "  restart ID\n"), (0, "restart ID")):
            with self.subTest(code=code, output=output):
                self.process.reset_mock()
                self.return_process(code=code, stdout=output)
                with self.assertRaises(ui.UIError):
                    self.backend.action(self.selected, "restart")
                self.assertEqual(self.process.call_count, 1)
                self.assertEqual(self.process.call_args.args[0], [str(ui.MANAGER), "help"])
        self.process.side_effect = subprocess.TimeoutExpired(["help"], 5)
        with self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "restart")

    def test_cdn_actions_validate_controller_scanner_and_nested_editor_helpers(self):
        trust = self.mock_checks()
        self.return_process(stdout="\n".join("  " + action + " ID" for action in ui.ACTIONS))
        for action in ("cdn-scan", "cdn-rounds", "cdn-preview"):
            with self.subTest(action=action):
                trust.reset_mock()
                self.backend.action(self.selected, action)
                for name in ("cdn-control.py", "cdn-endpoints.py", "tunnel-editor.py", "editor_tls.py", "access-manager.py", "profile-validation.py"):
                    self.assertIn(mock.call(ui.DOCTOR.with_name(name)), trust.call_args_list)
                self.assertIn(mock.call(ui.CORE), trust.call_args_list)

    def test_guided_rounds_require_trusted_scanner_helpers_before_launch(self):
        self.enterContext(mock.patch.object(ui, "inspect_tunnel", return_value=self.selected))
        for blocked in ("scanner-console.py", "scanner-engine.py"):
            with self.subTest(blocked=blocked):
                def trust(path):
                    if path.name == blocked:
                        raise ui.UIError("Unsafe scanner")
                self.process.reset_mock()
                self.return_process(stdout="  cdn-rounds ID\n")
                with mock.patch.object(ui, "trusted", side_effect=trust), self.assertRaises(ui.UIError):
                    self.backend.action(self.selected, "cdn-rounds")
                self.assertEqual(self.process.call_count, 1)
                self.assertEqual(self.process.call_args.args[0], [str(ui.MANAGER), "help"])

    def test_untrusted_cdn_helper_blocks_action_before_manager_mutation(self):
        self.enterContext(mock.patch.object(ui, "inspect_tunnel", return_value=self.selected))
        def trust(path):
            if path.name == "cdn-endpoints.py":
                raise ui.UIError("Unsafe scanner")
        self.enterContext(mock.patch.object(ui, "trusted", side_effect=trust))
        self.return_process(stdout="  cdn-scan ID\n")
        with self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "cdn-scan")
        self.assertEqual(self.process.call_count, 1)
        self.assertEqual(self.process.call_args.args[0], [str(ui.MANAGER), "help"])

    def test_old_manager_cdn_action_refused_without_upgrade(self):
        self.mock_checks()
        self.return_process(stdout="  edit ID\n  doctor ID\n")
        with self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "cdn")
        self.assertEqual(self.process.call_count, 1)

    def test_unknown_action_unmanaged_invalid_and_untrusted_refused(self):
        with self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "install")
        for selected in (tunnel(managed=False), tunnel(error="broken"), tunnel("../evil")):
            with self.subTest(id=selected.id, managed=selected.managed, error=selected.error), self.assertRaises(ui.UIError):
                self.backend.action(selected, "restart")
        with mock.patch.object(ui, "inspect_tunnel", side_effect=ui.UIError("unsafe")), self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "restart")
        with mock.patch.object(ui, "inspect_tunnel", return_value=self.selected), \
                mock.patch.object(ui, "trusted", side_effect=ui.UIError("unsafe executable")), self.assertRaises(ui.UIError):
            self.backend.action(self.selected, "restart")
        self.process.assert_not_called()

    def test_changed_config_refuses_stale_selection(self):
        for current in (tunnel(flags={"transport": "xhttp"}), tunnel(env={"ROLE": "egress"}), tunnel(signature="changed-private-data")):
            with self.subTest(current=current), mock.patch.object(ui, "inspect_tunnel", return_value=current), self.assertRaises(ui.UIError):
                self.backend.check_selected(self.selected)
        self.process.assert_not_called()

    def test_doctor_uses_isolated_python_fixed_selected_directory_and_timeout(self):
        trust = self.mock_checks()
        report = {"verdict": "configuration-checked-not-network-tested", "checks": [], "endpoints": [],
                  "schema": 1, "tunnel_id": self.selected.id, "time_utc": "2026-10-01T00:00:00Z"}
        self.return_process(stdout=json.dumps(report))
        for offline in (False, True):
            with self.subTest(offline=offline):
                trust.reset_mock()
                self.assertEqual(self.backend.doctor(self.selected, offline=offline), report)
                args, kwargs = self.process.call_args
                expected = [sys.executable, "-I", str(ui.DOCTOR), "--config-dir", str(self.registry / self.selected.id), "--timeout", "3"]
                self.assertEqual(args[0], expected + (["--offline"] if offline else []))
                self.assertFalse(kwargs.get("shell", False))
                self.assertEqual(kwargs["timeout"], 55)
                self.assertTrue(kwargs["capture_output"])
                self.assertIn(mock.call(ui.DOCTOR), trust.call_args_list)
                self.assertEqual(mock.call(ui.CORE) in trust.call_args_list, not offline)

    def test_doctor_timeout_hides_raw_process_output(self):
        self.mock_checks()
        self.process.side_effect = subprocess.TimeoutExpired(["private-token"], 55, output="secret")
        with self.assertRaises(ui.UIError) as caught:
            self.backend.doctor(self.selected)
        self.assertIn("55-second", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("private-token", str(caught.exception))

    def test_doctor_rejects_malformed_json_schema_and_contradictory_exit(self):
        self.mock_checks()
        cases = [(0, "private-token not JSON"), (0, "[]"), (0, "null"), (0, "{}"),
                 (1, json.dumps({"schema": 1, "tunnel_id": self.selected.id, "verdict": "carrier-authenticated"})),
                 (1, json.dumps({"schema": 1, "tunnel_id": self.selected.id, "verdict": "configuration-checked-not-network-tested"}))]
        for code, value in cases:
            with self.subTest(code=code, value=value):
                self.return_process(code=code, stdout=value)
                with self.assertRaises(ui.UIError) as caught:
                    self.backend.doctor(self.selected)
                self.assertNotIn("private-token", str(caught.exception))

    def test_doctor_rejects_wrong_schema_and_tunnel_identity(self):
        self.mock_checks()
        for metadata in ({}, {"schema": 2, "tunnel_id": self.selected.id}, {"schema": 1, "tunnel_id": "another"}):
            with self.subTest(metadata=metadata):
                report = {"verdict": "carrier-authenticated", **metadata}
                self.return_process(stdout=json.dumps(report))
                with self.assertRaises(ui.UIError):
                    self.backend.doctor(self.selected)

    def test_doctor_rechecks_config_after_probe(self):
        trust = self.enterContext(mock.patch.object(ui, "trusted"))
        self.return_process(stdout=json.dumps({"schema": 1, "tunnel_id": self.selected.id, "verdict": "carrier-authenticated"}))
        with mock.patch.object(ui, "inspect_tunnel", side_effect=[self.selected, tunnel(signature="changed")]), self.assertRaises(ui.UIError):
            self.backend.doctor(self.selected)
        self.assertEqual(self.process.call_count, 1)

    def test_doctor_rejects_malformed_nested_report(self):
        self.mock_checks()
        invalid = [{"verdict": None}, {"verdict": {"secret": "value"}},
                   {"verdict": "failed", "checks": None}, {"verdict": "failed", "endpoints": 42},
                   {"verdict": "failed", "endpoints": [{"checks": None}]},
                   {"verdict": "failed", "checks": [{"status": ["pass"], "stage": "DNS"}]}]
        for report in invalid:
            with self.subTest(report=report):
                self.return_process(stdout=json.dumps(report))
                with self.assertRaises(ui.UIError):
                    self.backend.doctor(self.selected)

    def test_doctor_rejects_oversized_output(self):
        self.mock_checks()
        self.return_process(stdout="x" * (ui.LIMIT + 1))
        with self.assertRaises(ui.UIError):
            self.backend.doctor(self.selected)

    def test_inventory_only_queries_status_and_marks_legacy_readonly(self):
        registry = mock.Mock()
        registry.exists.return_value = False
        self.return_process(stdout="ununknowntun.service loaded active running old tunnel\n"
                            "ununknowntun35-turkey-yta.service loaded active running isolated\n"
                            "evil.service loaded active running ignored\n")
        with mock.patch.object(ui, "REGISTRY", registry):
            found = self.backend.inventory()
        self.assertEqual(len(found), 2)
        self.assertTrue(all(not item.managed for item in found))
        self.assertEqual(self.process.call_count, 2)
        expected = [[ui.SYSTEMCTL, "list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "ununknowntun*.service"],
                    [ui.SYSTEMCTL, "list-unit-files", "--type=service", "--no-legend", "--no-pager", "ununknowntun*.service"]]
        for call, command in zip(self.process.call_args_list, expected):
            args, kwargs = call
            self.assertEqual(args[0], command)
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["timeout"], 5)

    def test_inventory_timeout_does_not_claim_tunnel_down(self):
        registry = mock.Mock()
        registry.exists.return_value = False
        self.process.side_effect = subprocess.TimeoutExpired(["systemctl"], 5)
        with mock.patch.object(ui, "REGISTRY", registry):
            self.assertEqual(self.backend.inventory(), [])
        self.assertIn("not proof", self.backend.notice)


class CliAndExportTests(OfflineCase):
    def test_icmp_list_mode_is_read_only_fixed_argv_without_tty(self):
        self.process.side_effect = None
        self.process.return_value = SimpleNamespace(returncode=0)
        with mock.patch.object(ui.sys, "platform", "linux"), mock.patch.object(ui.os, "geteuid", return_value=0), \
                mock.patch.object(ui.sys.stdin, "isatty", return_value=False), mock.patch.object(ui.sys.stdout, "isatty", return_value=False), \
                mock.patch.object(ui, "trusted"):
            self.assertEqual(ui.main(["--icmp-manage", "--list"]), 0)
        self.assertEqual(self.process.call_args.args[0], ["/usr/bin/python3", "-I", str(ui.ICMP_CONSOLE), "--list"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ui.main(["--list"])

    def test_icmp_cli_delegates_without_standard_inventory(self):
        with mock.patch.object(ui.sys, "platform", "linux"), mock.patch.object(ui.os, "geteuid", return_value=0), \
                mock.patch.object(ui.sys.stdin, "isatty", return_value=True), mock.patch.object(ui.sys.stdout, "isatty", return_value=True), \
                mock.patch.object(ui.Backend, "icmp_manager", return_value=3) as manager, \
                mock.patch.object(ui.Backend, "inventory", side_effect=AssertionError("inventory")):
            self.assertEqual(ui.main(["--icmp-manage"]), 3)
            manager.assert_called_once_with()
        self.process.assert_not_called()

    def test_icmp_cli_cannot_bypass_demo_or_platform_checks(self):
        for args in (["--demo"], ["--preview", "doctor"], ["--export-html", "unwritten.html"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                ui.main(["--icmp-manage"] + args)
        with mock.patch.object(ui.sys, "platform", "darwin"), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ui.main(["--icmp-manage"])
        self.process.assert_not_called()

    def test_cli_preview_never_uses_backend_or_system_commands(self):
        with mock.patch.object(ui.Backend, "inventory", side_effect=AssertionError("inventory")), \
                mock.patch.object(ui.Backend, "doctor", side_effect=AssertionError("doctor")), \
                mock.patch.object(ui.Backend, "action", side_effect=AssertionError("action")), \
                mock.patch.object(ui.sys.stdout, "isatty", return_value=False):
            for page in ("tunnels", "tuning", "doctor"):
                with self.subTest(page=page):
                    self.assertEqual(ui.main(["--preview", page, "--no-color", "--ascii"]), 0)
        self.process.assert_not_called()
        self.assertIn("SAMPLE DATA", self.stdout.getvalue())

    def test_cli_interactive_demo_quits_without_system_commands(self):
        class DemoApp(ui.App):
            def __init__(self, *args, **kwargs):
                kwargs["input_fn"] = lambda prompt: "q"
                super().__init__(*args, **kwargs)
        with mock.patch.object(ui, "App", DemoApp), mock.patch.object(ui.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(ui.sys.stdout, "isatty", return_value=True), \
                mock.patch.object(ui.Backend, "inventory", side_effect=AssertionError("inventory")):
            self.assertEqual(ui.main(["--demo", "--no-color"]), 0)
        self.process.assert_not_called()

    def test_live_cli_refuses_non_linux_or_non_root_before_inventory(self):
        for platform, uid in (("darwin", 0), ("linux", 1000)):
            with self.subTest(platform=platform, uid=uid), mock.patch.object(ui.sys, "platform", platform), \
                    mock.patch.object(ui.os, "geteuid", return_value=uid), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                ui.main([])
        self.process.assert_not_called()

    def test_export_html_escapes_preview_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "preview.html"
            with mock.patch.object(ui, "render", return_value='<script>alert("unsafe")</script> & text'):
                self.assertEqual(ui.main(["--export-html", str(destination)]), 0)
            result = destination.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", result)
            self.assertIn("&quot;unsafe&quot;", result)
            self.assertNotIn('<script>alert("unsafe")</script>', result)
            self.assertIn("sample data only", result)
            with self.assertRaises(FileExistsError):
                ui.export_html(destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), result)
        self.process.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
