#!/usr/bin/env python3
"""UNUNKNOWNTUN Control Room terminal UI, integrated 3.7 release. Python 3.8+, standard library only.

Opening this UI never installs, migrates, restarts or probes anything remotely.
Live actions delegate to the existing per-tunnel manager after explicit input.
Legacy/isolated services are visible but are never adopted by this interface.
"""
import argparse
import datetime
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import textwrap
import unicodedata
from dataclasses import dataclass, field

UI_VERSION = "3.7.0-preview.11"
REGISTRY = Path("/etc/ununknowntun/tunnels")
MANAGER = Path("/usr/local/bin/ununknowntunctl")
DOCTOR = Path("/opt/ununknowntun/share/tunnel-doctor.py")
SCANNER = Path("/opt/ununknowntun/share/scanner-console.py")
ICMP_CONSOLE = Path(__file__).absolute().with_name("direct-icmp-console.py")
CORE = Path("/usr/local/bin/ununknowntun")
SYSTEMCTL = "/usr/bin/systemctl"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LIMIT = 1024 * 1024
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
UNIT_RE = re.compile(r"ununknowntun[a-zA-Z0-9@_.:-]*\.service\Z")
ENV_KEYS = {"TUNNEL_NAME", "ROLE", "FOREIGN_DOMAIN", "FOREIGN_PROXY_PROVIDER",
            "IRAN_PROXY_PROVIDER", "FOREIGN_PORTS", "IRAN_ENTRY_PORTS", "TARGET_PORT", "CONNECT_HOST"}
FLAG_KEYS = {"transport", "mux", "ech-mode", "tls-fragment", "tls-fragment-size",
             "tls-fragment-interval", "sessions", "sessions-min", "max-streams",
             "max-memory", "utls-profile", "tls-min-version", "write-timeout", "edge-timeout",
             "connect", "sni", "ws-host", "ech-config", "xhttp-mode", "padding-bytes", "xhttp-padding-bytes",
             "path-rotation", "path-count", "path-grace", "path-legacy", "session-renewal"}
ACTIONS = {"edit", "edit-show", "customers", "usage", "start", "stop", "restart", "delete", "edit-apply",
           "cdn", "cdn-scan", "cdn-rounds", "cdn-preview", "cdn-status"}
MUTATING = {"edit", "customers", "start", "stop", "restart", "delete", "edit-apply", "cdn", "cdn-scan", "cdn-rounds"}
CDN_ACTIONS = {"cdn", "cdn-scan", "cdn-rounds", "cdn-preview", "cdn-status"}


class UIError(ValueError):
    """A deliberately secret-free explanation for the operator."""


def clean(value):
    # Config/log data must never control the terminal, including OSC/Bidi tricks.
    return "".join(c if not unicodedata.category(c).startswith("C") else " "
                   for c in str(value))[:2048]


def endpoint_label(value):
    """Display host/port labels, never URL credentials, query strings or paths."""
    if not isinstance(value, str) or not value:
        return "not explicit"
    if len(value) > 2048 or any(not re.fullmatch(r"[A-Za-z0-9.:[\]-]+", item) for item in value.split(",")):
        return "invalid endpoint (details hidden)"
    return value


def ech_source_label(value):
    # A resolver descriptor can contain a private DoH path/key. Display the
    # source category, not raw resolver URLs, file paths or ECH bytes.
    if not value or value == "auto":
        return "Automatic DNS discovery"
    if re.search(r"\+(?:udp|tcp|tls|https)://", value):
        return "Manual DNS descriptor (resolver hidden)"
    if value.startswith("base64:") or (not value.startswith("/") and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value)):
        return "Manual ECHConfigList (value hidden)"
    return "Manual source (not validated; value hidden)"


def cells(value):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1
               for c in value)


def fit(value, width):
    value = clean(value)
    if cells(value) <= width:
        return value
    result = ""
    for c in value:
        if cells(result + c) > max(0, width - 1):
            break
        result += c
    return result + ("…" if width else "")


def valid_id(value):
    return bool(ID_RE.fullmatch(value)) and "--" not in value


def trusted(path):
    """Refuse writable/unowned components, symlinks and non-regular files."""
    path = Path(path)
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise UIError("Unsafe ownership, permissions or symlink; action refused.")
    if not stat.S_ISREG(path.stat().st_mode):
        raise UIError("Expected a regular managed file; action refused.")


def read_small(path, check_trust=True):
    if check_trust:
        trusted(path)
    with Path(path).open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise UIError("Configuration is too large to inspect safely.")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise UIError("Configuration is not valid UTF-8.") from None


def parse_env(text):
    result, seen = {}, set()
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match or match[1] in seen:
            raise UIError("Malformed or duplicate deployment setting; no shell was executed.")
        key, raw = match.groups()
        seen.add(key)
        if key not in ENV_KEYS:
            continue
        # Bash %q can encode a display name using $'...'. Do not evaluate it.
        if key == "TUNNEL_NAME" and raw.startswith("$'"):
            result[key] = ""
            continue
        if "$" in raw or "`" in raw or any(ord(c) < 32 for c in raw):
            raise UIError("Dynamic deployment metadata is unsupported; no shell was executed.")
        try:
            words = shlex.split(raw)
        except ValueError:
            raise UIError("Invalid deployment quoting.") from None
        if len(words) > 1:
            raise UIError("Invalid deployment value.")
        result[key] = words[0] if words else ""
    if result.get("ROLE") not in ("origin", "egress"):
        raise UIError("Unknown tunnel role; action refused.")
    return result


def parse_flags(text):
    result, seen = {}, set()
    for line in text.splitlines():
        if not re.match(r"\s+-[a-z]", line):
            continue
        line = line.strip()
        if line.endswith("\\"):
            line = line[:-1].strip()
        try:
            words = shlex.split(line)
        except ValueError:
            raise UIError("Invalid launcher quoting; launcher was not executed.") from None
        if len(words) not in (1, 2) or not re.fullmatch(r"-[a-z][a-z0-9-]*", words[0]):
            raise UIError("Unsupported launcher layout; launcher was not executed.")
        key = words[0][1:]
        if key in seen:
            raise UIError("Duplicate launcher flag; action refused.")
        seen.add(key)
        if key not in FLAG_KEYS:
            continue
        value = words[1] if len(words) == 2 else "true"
        if "$" in value or "`" in value or any(ord(c) < 32 for c in value):
            raise UIError("Dynamic launcher settings are unsupported.")
        result[key] = ech_source_label(value) if key == "ech-config" else value
    return result


def child_env():
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(("BASH_FUNC_", "LD_", "DYLD_", "PYTHON")) or key in {
            "BASH_ENV", "ENV", "UNUNKNOWNTUN_TOKEN", "V7_TOKEN", "SHELLOPTS", "BASHOPTS"}:
            env.pop(key, None)
    env.update(PATH=SAFE_PATH, LC_ALL="C.UTF-8", SYSTEMD_PAGER="cat", PAGER="cat")
    return env


def validate_report(report):
    verdicts = {"carrier-authenticated", "configuration-checked-not-network-tested", "partial", "failed", "configuration-error"}
    if not isinstance(report, dict) or not isinstance(report.get("verdict"), str) or report["verdict"] not in verdicts:
        raise UIError("Doctor report schema is unsupported.")
    checks, endpoints = report.get("checks", []), report.get("endpoints", [])
    if not isinstance(checks, list) or not isinstance(endpoints, list) or len(checks) > 32 or len(endpoints) > 32:
        raise UIError("Doctor report has malformed or excessive checks.")
    all_checks = list(checks)
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("checks", []), list) or len(endpoint.get("checks", [])) > 32:
            raise UIError("Doctor endpoint report is malformed.")
        for key in ("endpoint", "leg", "sni"):
            if key in endpoint and not isinstance(endpoint[key], str):
                raise UIError("Doctor endpoint label is malformed.")
        all_checks.extend(endpoint.get("checks", []))
    for check in all_checks:
        if not isinstance(check, dict) or not isinstance(check.get("status"), str) or check["status"] not in ("pass", "fail", "skipped"):
            raise UIError("Doctor check status is malformed.")
        for key in ("stage", "detail", "error", "note", "next_step"):
            if key in check and not isinstance(check[key], str):
                raise UIError("Doctor check text is malformed.")
    for key in ("error", "time_utc"):
        if key in report and not isinstance(report[key], str):
            raise UIError("Doctor report text is malformed.")
    return report


@dataclass
class Tunnel:
    id: str
    name: str
    unit: str
    managed: bool = True
    state: str = "unknown"
    role: str = "unknown"
    env: dict = field(default_factory=dict)
    flags: dict = field(default_factory=dict)
    error: str = ""
    signature: str = field(default="", repr=False)


def inspect_tunnel(directory, check_trust=True):
    directory = Path(directory)
    if not valid_id(directory.name) or directory.is_symlink():
        raise UIError("Invalid managed tunnel directory.")
    env_text = read_small(directory / "deployment.env", check_trust)
    flags_text = read_small(directory / "run.sh", check_trust)
    env = parse_env(env_text)
    flags = parse_flags(flags_text)
    token = read_small(directory / "token", check_trust) if (directory / "token").exists() else ""
    cdn_path = directory / "cdn-endpoints.json"
    cdn_settings = read_small(cdn_path, check_trust) if cdn_path.exists() or cdn_path.is_symlink() else ""
    signature = hashlib.sha256((env_text + "\0" + flags_text + "\0" + token + "\0" + cdn_settings).encode()).hexdigest()
    return Tunnel(directory.name, env.get("TUNNEL_NAME") or directory.name,
                  "ununknowntun@" + directory.name + ".service", role=env["ROLE"], env=env, flags=flags, signature=signature)


class Backend:
    def __init__(self):
        self.notice = ""

    def inventory(self):
        found = []
        self.notice = ""
        try:
            for directory in sorted(REGISTRY.iterdir()) if REGISTRY.exists() else []:
                if not directory.is_dir() or not valid_id(directory.name):
                    continue
                try:
                    found.append(inspect_tunnel(directory))
                except (UIError, OSError):
                    found.append(Tunnel(directory.name, directory.name, "ununknowntun@" + directory.name + ".service",
                                        error="Configuration unreadable or unsafe; actions disabled."))
        except OSError:
            self.notice = "Managed registry could not be read. No changes were made."
        try:
            reply = subprocess.run([SYSTEMCTL, "list-units", "--all", "--type=service", "--no-legend",
                                    "--no-pager", "--plain", "ununknowntun*.service"],
                                   capture_output=True, text=True, timeout=5, env=child_env())
            if reply.returncode:
                raise UIError("systemd status unavailable")
            units = {}
            for line in reply.stdout.splitlines():
                values = line.split()
                if len(values) >= 4 and UNIT_RE.fullmatch(values[0]):
                    units[values[0]] = values[2] + "/" + values[3]
            try:
                installed = subprocess.run([SYSTEMCTL, "list-unit-files", "--type=service", "--no-legend",
                                            "--no-pager", "ununknowntun*.service"], capture_output=True,
                                           text=True, timeout=5, env=child_env())
                if installed.returncode:
                    raise UIError("Unit file inventory unavailable")
                for line in installed.stdout.splitlines():
                    values = line.split()
                    if values and UNIT_RE.fullmatch(values[0]) and values[0] != "ununknowntun@.service":
                        units.setdefault(values[0], "not-loaded")
            except (OSError, subprocess.TimeoutExpired, UIError):
                self.notice = "Loaded services shown; installed-but-unloaded service inventory unavailable."
            for tunnel in found:
                tunnel.state = units.pop(tunnel.unit, "not-loaded")
            for unit, state in sorted(units.items()):
                found.append(Tunnel(unit, unit, unit, managed=False, state=state))
        except (OSError, subprocess.TimeoutExpired, UIError):
            self.notice = "Service status unavailable; this is not proof that a tunnel is down."
        return found

    def check_selected(self, tunnel):
        if not tunnel.managed or tunnel.error or not valid_id(tunnel.id):
            raise UIError("Only a healthy managed configuration can be selected for this action.")
        current = inspect_tunnel(REGISTRY / tunnel.id)
        if current.signature != tunnel.signature or current.env != tunnel.env or current.flags != tunnel.flags:
            raise UIError("Configuration changed since refresh. Refresh and review before continuing.")
        return current

    def action(self, tunnel, action):
        if action not in ACTIONS:
            raise UIError("Unknown action; nothing was run.")
        self.check_selected(tunnel)
        trusted(MANAGER)
        # Older managers return exit 0 plus help for unsupported commands.
        # Verify the existing help advertises the exact command before running.
        try:
            help_result = subprocess.run([str(MANAGER), "help"], capture_output=True,
                                         text=True, timeout=5, env=child_env())
        except (OSError, subprocess.TimeoutExpired):
            raise UIError("Could not verify installed manager capabilities; action refused.") from None
        supported = set()
        for line in help_result.stdout[:LIMIT].splitlines():
            match = re.match(r"^  ([a-z][a-z-]*(?:\|[a-z][a-z-]*)*)(?:\s|$)", line)
            if match:
                supported.update(match[1].split("|"))
        if help_result.returncode or action not in supported:
            raise UIError("Installed manager does not advertise this action. No upgrade or mutation was attempted.")
        if action in CDN_ACTIONS:
            for helper in ("cdn-control.py", "cdn-endpoints.py", "tunnel-editor.py", "editor_tls.py", "access-manager.py", "profile-validation.py"):
                trusted(DOCTOR.with_name(helper))
            if action == "cdn-rounds":
                trusted(SCANNER)
                trusted(SCANNER.with_name("scanner-engine.py"))
            if action in {"cdn", "cdn-scan", "cdn-rounds", "cdn-preview"}:
                trusted(CORE)
        elif action in {"edit", "edit-apply", "edit-show"}:
            for helper in ("tunnel-editor.py", "editor_tls.py", "access-manager.py", "profile-validation.py"):
                trusted(DOCTOR.with_name(helper))
        elif action in {"usage", "customers"}:
            trusted(DOCTOR.with_name("access-manager.py"))
        # Delegate locks, edit plans, rollback and paired synchronization to the
        # installed manager. Never call the installer or source deployment.env.
        try:
            result = subprocess.run([str(MANAGER), action, tunnel.id], env=child_env())
        except OSError:
            raise UIError("Installed manager could not start. Nothing was installed by this UI.") from None
        return result.returncode

    def doctor(self, tunnel, offline=False):
        self.check_selected(tunnel)
        trusted(DOCTOR)
        if not offline:
            trusted(CORE)
        args = [sys.executable, "-I", str(DOCTOR), "--config-dir", str(REGISTRY / tunnel.id), "--timeout", "3"]
        if offline:
            args.append("--offline")
        # Existing doctor uses at most 16 candidates; the UI additionally bounds
        # the complete command. No listener or service is started by the probe.
        try:
            reply = subprocess.run(args, capture_output=True, text=True, timeout=55, env=child_env())
        except subprocess.TimeoutExpired:
            raise UIError("Doctor reached the 55-second total limit; no complete result. Test fewer endpoints using the CLI.") from None
        except OSError:
            raise UIError("Installed Doctor helper could not start.") from None
        if len(reply.stdout) + len(reply.stderr) > LIMIT:
            raise UIError("Doctor output was unexpectedly large; not displayed.")
        try:
            report = json.loads(reply.stdout if reply.stdout.strip() else reply.stderr)
        except (ValueError, TypeError):
            raise UIError("Doctor did not return a valid report. Use the matching 3.5+ helper; raw output was withheld.") from None
        validate_report(report)
        if report["verdict"] != "configuration-error" and (report.get("schema") != 1 or report.get("tunnel_id") != tunnel.id):
            raise UIError("Doctor report does not match this tunnel or supported schema.")
        if reply.returncode and report.get("verdict") in ("carrier-authenticated", "configuration-checked-not-network-tested"):
            raise UIError("Doctor exit status contradicts its report; success was not accepted.")
        self.check_selected(tunnel)
        report.setdefault("time_utc", datetime.datetime.now(datetime.timezone.utc).isoformat())
        return report

    def scanner(self):
        """Open the independent interactive scanner; no selected tunnel needed."""
        for path in (MANAGER, SCANNER, SCANNER.with_name("scanner-engine.py")):
            trusted(path)
        try:
            reply = subprocess.run([str(MANAGER), "help"], capture_output=True,
                                   text=True, timeout=5, env=child_env())
            if reply.returncode or not re.search(r"(?m)^  scanner\s", reply.stdout[:LIMIT]):
                raise UIError("Installed manager does not advertise the full scanner. Install the matching release first.")
            # The manager validates the optional private Python environment and
            # launches with -I. Inherit this terminal for the English wizard.
            return subprocess.run([str(MANAGER), "scanner"], env=child_env()).returncode
        except (OSError, subprocess.TimeoutExpired):
            raise UIError("The full scanner could not start. No installation was attempted.") from None

    def icmp_manager(self, list_only=False):
        """Manage separately installed endpoints using their own trusted helpers."""
        try:
            trusted(ICMP_CONSOLE)
            command = ["/usr/bin/python3", "-I", str(ICMP_CONSOLE)]
            if list_only:
                command.append("--list")
            return subprocess.run(command, env=child_env()).returncode
        except OSError:
            raise UIError("Direct ICMP manager is not staged beside this UI. Use the matching installer or installed UI.") from None


def demo_tunnels():
    return [Tunnel("sample-europe", "Europe / primary", "sample", state="active/running", role="origin",
                   env={"FOREIGN_DOMAIN": "edge.example", "FOREIGN_PROXY_PROVIDER": "cloudflare", "IRAN_PROXY_PROVIDER": "none",
                        "IRAN_ENTRY_PORTS": "2055", "FOREIGN_PORTS": "443", "TARGET_PORT": "18082", "CONNECT_HOST": "192.0.2.10"},
                   flags={"transport": "wss", "mux": "on", "ech-mode": "off", "tls-fragment": "off",
                          "sessions-min": "2", "sessions": "8", "max-streams": "256", "tls-min-version": "1.3",
                          "connect": "192.0.2.10:443", "sni": "edge.example", "ws-host": "edge.example", "ech-config": "Automatic DNS discovery",
                          "padding-bytes": "0", "xhttp-padding-bytes": "0", "xhttp-mode": "auto"}),
            Tunnel("sample-direct", "Direct / secondary", "sample2", state="inactive/dead", role="egress",
                   env={"FOREIGN_DOMAIN": "direct.example", "FOREIGN_PROXY_PROVIDER": "none", "IRAN_PROXY_PROVIDER": "none"},
                   flags={"transport": "xhttp", "mux": "off"}),
            Tunnel("ununknowntun-legacy.service", "ununknowntun-legacy.service", "sample3", managed=False, state="active/running")]


class Screen:
    def __init__(self, width=94, color=False, ascii_only=False):
        self.width = max(32, min(width, 112))
        self.color = color
        self.ascii = ascii_only
        self.lines = []

    def ink(self, text, tone="normal"):
        codes = {"normal": "", "teal": "\033[36m", "muted": "\033[90m", "good": "\033[32m",
                 "warn": "\033[33m", "bad": "\033[31m", "title": "\033[1;36m"}
        return codes[tone] + text + "\033[0m" if self.color else text

    def border(self, position="middle"):
        if self.ascii:
            row = "+" + "-" * (self.width - 2) + "+"
        else:
            left, right = {"top": ("╭", "╮"), "middle": ("├", "┤"), "bottom": ("╰", "╯")}[position]
            row = left + "─" * (self.width - 2) + right
        self.lines.append(self.ink(row, "muted"))

    def row(self, text="", tone="normal"):
        text = clean(text)
        if self.ascii:
            text = text.encode("ascii", "replace").decode("ascii")
        text = fit(text, self.width - 6)
        if self.ascii:
            text = text.replace("…", ".")
        vertical = "|" if self.ascii else "│"
        self.lines.append(self.ink(vertical, "muted") + "  " + self.ink(text, tone) +
                          " " * (self.width - 4 - cells(text)) + self.ink(vertical, "muted"))

    def note(self, text, tone="muted"):
        for line in textwrap.wrap(clean(text), max(10, self.width - 6)):
            self.row(line, tone)

    def pair(self, label, value):
        if self.width < 60:
            self.row(label, "muted")
            self.row("  " + str(value))
        else:
            self.row(label.ljust(23) + str(value))

    def result(self):
        return "\n".join(self.lines) + "\n"


def diagnostic_rows(report):
    if report is None:
        return [("WAIT", "Configuration", "Not checked in this UI session."),
                ("WAIT", "DNS / TCP / TLS", "No network probe has run."),
                ("WAIT", "Tunnel authentication", "Service active does not prove authentication."),
                ("TODO", "Real client payload", "Test with a real client; never inferred from TLS.")]
    output = []
    status_names = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP"}
    for check in report.get("checks", []):
        if isinstance(check, dict):
            output.append((status_names.get(check.get("status"), "WAIT"), clean(check.get("stage", "check")), ""))
    for endpoint in report.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        for check in endpoint.get("checks", []):
            if not isinstance(check, dict):
                continue
            name = str(endpoint.get("endpoint", "endpoint")) + " / " + str(check.get("stage", "check"))
            detail = check.get("error") or check.get("note") or check.get("next_step", "")
            if check.get("status") == "fail" and check.get("detail"):
                detail = check["detail"] + " | " + detail
            output.append((status_names.get(check.get("status"), "WAIT"), clean(name), clean(detail)))
    if report.get("error"):
        output.append(("FAIL", "Configuration", clean(report["error"])))
    if not report.get("endpoints"):
        output.append(("WAIT", "Network / authentication", "Not tested by this report."))
    output.append(("TODO", "Real client payload", "A real client test is still required."))
    return output


def render(tunnels, selected=0, page="tunnels", report=None, demo=False, width=94, color=False, ascii_only=False, notice=""):
    s = Screen(width, color, ascii_only)
    t = tunnels[selected] if tunnels and 0 <= selected < len(tunnels) else None
    s.border("top")
    s.row("ununknowntunctl companion  /  terminal UI " + UI_VERSION, "muted")
    s.border()
    s.row()
    s.row("UNUNKNOWNTUN                                      @SIKDPI", "title")
    s.row("sik-dpi  /  CONTROL ROOM", "teal")
    s.row("SAMPLE DATA - DEMO ONLY / no actions or network" if demo else "LIVE LOCAL VIEW / no automatic changes",
          "warn" if demo else "muted")
    s.row()
    s.border()
    tabs = [("1", "tunnels", "Tunnels"), ("2", "tuning", "Tuning"), ("3", "doctor", "Doctor")]
    if width < 60:
        for key, name, title in tabs:
            s.row(("> " if name == page else "  ") + key + "  " + title, "teal" if name == page else "muted")
    else:
        s.row("    ".join(("[ " if page == name else "  ") + key + " " + title + (" ]" if page == name else "  ")
                           for key, name, title in tabs), "teal")
    s.border()
    if t:
        s.row(t.name, "title")
        s.pair("Service state", t.state + (" (sample)" if demo else ""))
        if t.managed and not t.error:
            role = {"origin": "IRAN / origin", "egress": "FOREIGN / egress"}.get(t.role, "Unknown")
            s.pair("This server", role)
            carrier = t.flags.get("transport", "unknown").upper()
            proxy = t.env.get("FOREIGN_PROXY_PROVIDER", "unknown")
            s.note("IRAN IP + ports  ->  " + proxy + " / " + carrier + "  ->  FOREIGN", "teal")
        else:
            s.note(t.error or "READ ONLY: legacy / isolated service; not owned by the managed registry.", "warn")
    else:
        s.note("No tunnels found. This UI does not install or migrate services.", "warn")
    s.border()
    if page == "tunnels":
        s.row("YOUR TUNNELS", "muted")
        for index, tunnel in enumerate(tunnels):
            marker = ">" if index == selected else " "
            s.row(f"{marker} t {index+1}   {tunnel.name}", "teal" if index == selected else "normal")
            scope = "blocked config" if tunnel.error else "managed" if tunnel.managed else "read only"
            s.row("        " + tunnel.state + " / " + scope, "muted")
        s.row()
        s.note("t NUMBER Select    e Edit    c Customers    u Usage")
        s.note("n CDN settings    b Guided scan rounds    s Auto-policy scan/apply    v CDN status")
        s.note("o Service actions (start / stop / restart / remove)")
        s.note("Use the installer to add tunnels. Direct ICMP: press i for its dedicated manager.")
    elif page == "tuning":
        if t and t.managed and not t.error:
            for label, value in [("Carrier", t.flags.get("transport", "unknown")),
                                 ("Foreign proxy", t.env.get("FOREIGN_PROXY_PROVIDER", "unknown")),
                                 ("Iran proxy", t.env.get("IRAN_PROXY_PROVIDER", "unknown")),
                                 ("Foreign domain", t.env.get("FOREIGN_DOMAIN", "unknown")),
                                 ("Endpoint override", endpoint_label(t.env.get("CONNECT_HOST", "")) if t.env.get("CONNECT_HOST") else "Original domain / IP"),
                                 ("Dial endpoint", endpoint_label(t.flags.get("connect", ""))),
                                 ("TLS SNI", endpoint_label(t.flags.get("sni", ""))),
                                 ("HTTP Host", endpoint_label(t.flags.get("ws-host", ""))),
                                 ("Iran entry ports", t.env.get("IRAN_ENTRY_PORTS", "not recorded")),
                                 ("Foreign TLS ports", t.env.get("FOREIGN_PORTS", "not recorded")),
                                 ("Foreign target port", t.env.get("TARGET_PORT", "not recorded")),
                                 ("MUX", t.flags.get("mux", "not explicit")),
                                 ("ECH", t.flags.get("ech-mode", "not explicit")),
                                 ("ECH source", t.flags.get("ech-config", "Automatic DNS discovery")),
                                 ("XHTTP mode", t.flags.get("xhttp-mode", "packet-up (legacy default)")),
                                 ("Frame padding bytes", t.flags.get("padding-bytes", "0 (off)")),
                                 ("XHTTP HTTP padding", t.flags.get("xhttp-padding-bytes", "0 (off)")),
                                 ("TLS fragment", t.flags.get("tls-fragment", "not explicit")),
                                 ("Fragment size", t.flags.get("tls-fragment-size", "not explicit")),
                                 ("Session min / max", t.flags.get("sessions-min", "?") + " / " + t.flags.get("sessions", "?")),
                                 ("Path rotation / count", t.flags.get("path-rotation", "0") + " / " + t.flags.get("path-count", "3")),
                                 ("Carrier renewal", t.flags.get("session-renewal", "0")),
                                 ("Max streams", t.flags.get("max-streams", "not explicit"))]:
                s.pair(label, value)
            s.row()
            s.note("e Open existing full editor    a Apply peer update")
            s.note("n CDN settings    b Guided scan rounds    p Preview scan    s Auto-policy scan/apply    v CDN status")
            s.note("CDN scanning is opt-in and Cloudflare-only. A scan/apply may restart this tunnel.")
            s.note("TLS modes: ordinary / strict ECH / ClientHello fragmentation. Streaming CDN compatibility needs live testing.")
            s.note("Values above are saved configuration, not proof of a negotiated feature. The editor previews each change and handles paired updates.")
        else:
            s.note("Editing is unavailable for unmanaged or unreadable configurations.", "warn")
    else:
        if report:
            s.pair("Report (UTC)", report.get("time_utc", "unknown"))
            s.pair("Verdict", report.get("verdict", "unknown"))
            s.note("Report is a snapshot, not continuous monitoring.")
        for status, label, detail in diagnostic_rows(report):
            tone = {"PASS": "good", "FAIL": "bad", "SKIP": "warn"}.get(status, "muted")
            s.row(status.ljust(7) + label, tone)
            if detail:
                s.note("       " + detail)
        s.row()
        s.note("d Run configured endpoint checks    f Check config offline")
        s.note("No port-range scanning. No TLS bypass. No guessed root cause.")
    if notice:
        s.border()
        s.note(notice, "warn")
    s.border()
    s.note("1 Tunnels   2 Tuning   3 Doctor   r Refresh   q Exit")
    s.note("k Full SIKDPI scanner (IP / SNI / REALITY / speed / exports)")
    s.note("i Direct ICMP manager (status / forwarding info / services / diagnostics)")
    s.note("ununknowntun > " + page + " _", "teal")
    s.border("bottom")
    return s.result()


class App:
    def __init__(self, demo=False, color=True, ascii_only=False, backend=None, input_fn=input):
        self.demo, self.color, self.ascii = demo, color, ascii_only
        self.backend = backend or Backend()
        self.input = input_fn
        self.tunnels = []
        self.selected = 0
        self.page = "tunnels"
        self.reports = {}
        self.notice = ""

    def refresh(self):
        previous = self.tunnels[self.selected].id if self.tunnels else None
        self.tunnels = demo_tunnels() if self.demo else self.backend.inventory()
        self.selected = next((i for i, tunnel in enumerate(self.tunnels) if tunnel.id == previous), 0)
        self.notice = "" if self.demo else self.backend.notice
        # Never show cached PASS after refreshing possibly changed config.
        self.reports.clear()

    def choose(self):
        if not self.tunnels:
            raise UIError("Select a managed tunnel first.")
        tunnel = self.tunnels[self.selected]
        if not tunnel.managed or tunnel.error:
            raise UIError("This entry is read only. No migration or service action is offered.")
        return tunnel

    def dispatch(self, command):
        command = command.strip()
        if command in ("q", "0", "exit"):
            return False
        if command in ("1", "2", "3"):
            self.page = {"1": "tunnels", "2": "tuning", "3": "doctor"}[command]
        elif command == "r":
            self.refresh()
        elif command == "i":
            if self.demo:
                raise UIError("DEMO ONLY: no Direct ICMP management action executed.")
            code = self.backend.icmp_manager()
            print("Direct ICMP manager returned exit=" + str(code) + ".")
            self.input("Press Enter to return to the dashboard. ")
            self.refresh()
        elif command == "k":
            if self.demo:
                raise UIError("DEMO ONLY: no scanner or network action executed.")
            code = self.backend.scanner()
            print("Scanner returned exit=" + str(code) + "; results do not prove UNUNKNOWNTUN authentication.")
            self.input("Press Enter to return to the dashboard. ")
            self.refresh()
        elif re.fullmatch(r"t [0-9]+", command):
            index = int(command.split()[1]) - 1
            if not 0 <= index < len(self.tunnels):
                raise UIError("Choose an existing tunnel number; selection was kept.")
            self.selected = index
        elif command in ("d", "f", "e", "a", "c", "u", "o", "n", "b", "p", "s", "v"):
            if self.demo:
                raise UIError("DEMO ONLY: no action executed. Live mode uses installed tunnel data.")
            tunnel = self.choose()
            if command in ("d", "f"):
                self.page = "doctor"
                self.reports.pop(tunnel.id, None)
                if command == "d" and self.input("Probe only this tunnel's configured endpoints? [y/N] ").strip().lower() != "y":
                    self.notice = "Network probe cancelled."
                    return True
                print("Checking configuration..." if command == "f" else "Testing configured endpoints (up to 55 seconds); no service changes...")
                self.reports[tunnel.id] = self.backend.doctor(tunnel, offline=command == "f")
            else:
                action = {"e": "edit", "a": "edit-apply", "c": "customers", "u": "usage",
                          "n": "cdn", "b": "cdn-rounds", "p": "cdn-preview", "s": "cdn-scan", "v": "cdn-status"}.get(command)
                if command == "o":
                    print("1 Start   2 Stop   3 Restart   4 Remove tunnel   0 Cancel")
                    choice = self.input("Service action > ").strip()
                    if choice == "0":
                        return True
                    action = {"1": "start", "2": "stop", "3": "restart", "4": "delete"}.get(choice)
                    if not action:
                        raise UIError("Unknown service action; nothing changed.")
                if action in MUTATING:
                    print("Selected tunnel: " + clean(tunnel.id))
                    if action in {"cdn", "cdn-scan", "cdn-rounds"}:
                        print("CDN settings may change scheduled scanning; scan/apply may restart only this tunnel.")
                        print("No scan or automatic update is enabled merely by opening the dashboard.")
                    else:
                        print("Editing may interrupt this tunnel. Paired changes may need synchronization.")
                    if self.input("Type the tunnel ID to open " + action + " (Enter cancels): ").strip() != tunnel.id:
                        self.notice = "Cancelled; no action executed."
                        return True
                self.reports.pop(tunnel.id, None)
                code = self.backend.action(tunnel, action)
                print("Command returned exit=" + str(code) + "; this alone does not prove client connectivity.")
                self.input("Press Enter to return to the dashboard. ")
                self.refresh()
        elif command:
            raise UIError("Unknown option. Choose 1, 2, 3, t NUMBER, or a listed letter.")
        return True

    def run(self):
        self.refresh()
        while True:
            if sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
                print("\033[2J\033[H", end="")
            selected = self.tunnels[self.selected] if self.tunnels else None
            print(render(self.tunnels, self.selected, self.page, self.reports.get(selected.id) if selected else None,
                         self.demo, shutil.get_terminal_size((94, 30)).columns, self.color, self.ascii, self.notice), end="")
            try:
                command = self.input("ununknowntun > ")
                self.notice = ""
                if not self.dispatch(command):
                    return 0
            except UIError as error:
                self.notice = str(error)
            except OSError:
                self.notice = "A local file or command could not be accessed. No automatic repair was attempted."


def export_html(path):
    """A local, self-contained visual review of the same terminal renderer."""
    panels = []
    for page in ("tunnels", "tuning", "doctor"):
        preview = render(demo_tunnels(), page=page, demo=True, width=94)
        panels.append('<section id="' + page + '"><h2>' + page.title() + '</h2><pre>' + html.escape(preview) + '</pre></section>')
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UNUNKNOWNTUN — Terminal UI preview</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf2f4;color:#263847;font-family:system-ui,sans-serif}
header{max-width:1080px;margin:64px auto 24px;padding:0 30px}small{letter-spacing:.16em;color:#087e80;font-weight:700}
h1{font-size:clamp(32px,6vw,58px);letter-spacing:-.05em;margin:14px 0}p{line-height:1.6;color:#60707e;max-width:720px}
nav{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}a{color:#087e80;border:1px solid #bfd4d9;border-radius:9px;padding:11px 19px;text-decoration:none;background:#fff}
main{max-width:1080px;margin:auto;padding:0 30px 60px}section{scroll-margin:30px;background:#f8fafb;border:1px solid #cbd6de;border-radius:18px;margin:26px 0;box-shadow:0 12px 38px #334b5810;overflow:hidden}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.14em;padding:18px 24px;background:white;border-bottom:1px solid #d9e1e6;margin:0;color:#087e80}
pre{font:clamp(10px,1.28vw,15px)/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:22px;margin:0;overflow:auto;color:#234252}
.notice{border-left:3px solid #0d8587;padding-left:16px}footer{color:#60707e;font-size:13px}
</style><header><small>SIK-DPI / @SIKDPI</small><h1>One calm control room.</h1>
<p>A terminal companion for UNUNKNOWNTUN. Tunnels, tuning and evidence-based diagnostics — without replacing the tunnel core.</p>
<p class="notice"><strong>Visual preview · sample data only.</strong> No servers were contacted. No diagnosis was run. The live program reads local installed tunnels. This page is not a web control panel.</p>
<nav><a href="#tunnels">01 Tunnels</a><a href="#tuning">02 Tuning</a><a href="#doctor">03 Doctor</a></nav></header><main>'''
    document += "".join(panels) + '<footer>UNUNKNOWNTUN UI ' + UI_VERSION + ' · Python standard library · SSH / Termius friendly · no browser service</footer></main></html>'
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(document)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="sample data; all live actions disabled")
    parser.add_argument("--preview", choices=("tunnels", "tuning", "doctor"), help="print a sample screen and exit; no system access")
    parser.add_argument("--export-html", metavar="NEW_FILE", help="create a static sample preview; never overwrites")
    parser.add_argument("--icmp-manage", action="store_true", help="open the dedicated installed Direct ICMP manager")
    parser.add_argument("--list", action="store_true", help="with --icmp-manage: read-only endpoint inventory without a terminal")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--ascii", action="store_true", help="ASCII borders for restricted terminal fonts")
    args = parser.parse_args(argv)
    if args.icmp_manage and (args.demo or args.preview or args.export_html):
        parser.error("--icmp-manage cannot be combined with demo, preview or export modes.")
    if args.list and not args.icmp_manage:
        parser.error("--list requires --icmp-manage.")
    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    if args.preview:
        print(render(demo_tunnels(), page=args.preview, demo=True, width=shutil.get_terminal_size((94, 30)).columns,
                     color=color, ascii_only=args.ascii), end="")
        return 0
    if args.export_html:
        export_html(args.export_html)
        return 0
    if not args.demo and (sys.platform != "linux" or os.geteuid() != 0):
        parser.error("Live mode requires root on the Linux server. Use --demo locally; nothing is installed automatically.")
    if not args.list and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        parser.error("Interactive mode requires a terminal. Use --preview for a safe, non-interactive sample.")
    try:
        if args.icmp_manage:
            return Backend().icmp_manager(list_only=True) if args.list else Backend().icmp_manager()
        return App(args.demo, color, args.ascii).run()
    except UIError as error:
        print("[STOP] " + str(error), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nUI closed. No automatic stop, restart or rollback was requested by the UI.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
