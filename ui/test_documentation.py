"""Offline checks for the equivalent English, Russian and Chinese guides.

Only documentation and local file metadata are read. This module does not import
the UI, execute documented commands, start services or make network requests.
Run with: python3 test_documentation.py
"""

import ipaddress
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
GUIDE_NAMES = ("README.md", "README.ru.md", "README.zh-CN.md")
CONTROL_KEYS = ("1", "2", "3", "t 2", "e", "a", "c", "u", "o", "n", "b", "p", "s", "v", "k", "i", "f", "d", "r", "q")
OPERATIONAL_LITERALS = (
    "UNUNKNOWNTUN", "3.5", "V1", "python3", "systemd",
    "/etc/ununknowntun/tunnels", "/usr/local/bin/ununknowntunctl",
    "ununknowntun.service", "ununknowntun-germany.service", "ununknowntun35-turkey-yta.service",
    "--demo", "--preview doctor", "--ascii", "--no-color", "NO_COLOR",
    "active/running", "WAIT", "PASS", "TODO", "peer.env",
    "test_terminal_ui.py", "VALIDATION.md", "SHA256SUMS", "--export-html", "run-tests.py",
    "3.7.0-preview.11", "Dial endpoint", "TLS SNI", "HTTP Host", "ECHConfigList",
    "cdn-scan", "cdn-status", "TLS Hello over DNS", "packet-up", "stream-up", "stream-one",
    "Frame padding bytes", "XHTTP HTTP padding",
    "ununknowntunctl scanner", "SIKDPI", "REALITY", "ununknowntunctl ui", "cdn-rounds", "9) Control Room UI",
)
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))


def fenced_blocks(document):
    """Return language/content pairs and reject unterminated Markdown fences."""
    blocks = []
    opening = None
    content = []
    for line_number, line in enumerate(document.splitlines(), 1):
        if opening is None:
            match = re.match(r"^ {0,3}(`{3,}|~{3,})([^\r\n]*)$", line)
            if match:
                marker, language = match.groups()
                opening = (marker, language.strip(), line_number)
                content = []
        else:
            marker, language, _ = opening
            if re.fullmatch(r" {0,3}" + re.escape(marker[0]) +
                            r"{" + str(len(marker)) + r",}\s*", line):
                blocks.append((language, "\n".join(content)))
                opening = None
            else:
                content.append(line)
    if opening is not None:
        raise ValueError("Unclosed Markdown fence at line {}".format(opening[2]))
    return blocks


def markdown_targets(document):
    """Read inline links/images and reference definitions used by these guides."""
    targets = re.findall(r"!?\[[^\]\n]*\]\(\s*<?([^\s)>]+)>?(?:\s+[^)]*)?\)", document)
    targets.extend(re.findall(r"^ {0,3}\[[^\]\n]+\]:\s*<?([^\s>]+)>?", document, re.MULTILINE))
    return targets


def ip_literals(document):
    candidates = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", document)
    candidates.extend(re.findall(
        r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?![\w:])", document))
    for candidate in candidates:
        try:
            yield ipaddress.ip_address(candidate)
        except ValueError:
            # A version number or punctuation is not an IP address.
            continue


class DocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guides = {}
        cls.read_errors = {}
        for name in GUIDE_NAMES:
            try:
                cls.guides[name] = (ROOT / name).read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError) as error:
                cls.read_errors[name] = str(error)

    def test_all_four_guides_are_readable_utf8(self):
        self.assertEqual(self.read_errors, {}, "Missing or invalid UTF-8 guide")
        self.assertEqual(set(self.guides), set(GUIDE_NAMES))
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                self.assertTrue(document.strip(), "Guide is empty")
                self.assertNotIn("\ufffd", document, "Unicode replacement character")
                self.assertNotIn("\x00", document, "NUL character")
                self.assertFalse(document.startswith("\ufeff"), "Unexpected UTF-8 BOM")

    def test_markdown_fences_are_balanced(self):
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                fenced_blocks(document)

    def test_bash_blocks_are_identical_and_in_order(self):
        self.assertIn("README.md", self.guides)
        expected = [content for language, content in fenced_blocks(self.guides["README.md"])
                    if language == "bash"]
        self.assertTrue(expected, "Canonical guide has no bash examples")
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                actual = [content for language, content in fenced_blocks(document) if language == "bash"]
                self.assertEqual(actual, expected, "Bash examples must match the canonical guide exactly")

    def test_command_table_keys_are_complete_and_in_order(self):
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                keys = re.findall(r"^\|\s*`([^`]+)`\s*\|", document, re.MULTILINE)
                self.assertEqual(tuple(keys), CONTROL_KEYS)

    def test_language_navigation_links_all_shipped_relative_guides(self):
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                paragraphs = re.split(r"\n\s*\n", document.strip())
                self.assertGreaterEqual(len(paragraphs), 2)
                self.assertEqual(tuple(markdown_targets(paragraphs[1])),
                                 ("README.md", "README.ru.md", "README.zh-CN.md"),
                                 "Keep all shipped relative language links immediately below the title")

    def test_local_link_targets_exist_in_source_and_exclude_stale_assets(self):
        for name, document in self.guides.items():
            for target in markdown_targets(document):
                with self.subTest(guide=name, target=target):
                    parsed = urlsplit(target)
                    self.assertNotEqual(parsed.scheme.lower(), "file", "Use package-relative asset links")
                    if parsed.scheme or parsed.netloc or not parsed.path:
                        continue
                    relative = Path(unquote(parsed.path))
                    self.assertFalse(relative.is_absolute(), "Use package-relative asset links")
                    self.assertNotIn("..", relative.parts, "Link leaves the package directory")
                    self.assertNotIn(str(relative), {"preview-terminal.png", "VALIDATION.txt", "build.py", "package-complete.py", "README.fa.txt"})
                    self.assertTrue((ROOT / relative).is_file(),
                                    "Missing local link target: " + target)

    def test_operational_literals_are_preserved(self):
        for name, document in self.guides.items():
            for literal in OPERATIONAL_LITERALS:
                with self.subTest(guide=name, literal=literal):
                    self.assertIn(literal, document)

    def test_doctor_time_limits_are_preserved_together(self):
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                paragraphs = re.split(r"\n\s*\n", document)
                limits = [paragraph for paragraph in paragraphs
                          if re.search(r"(?<![0-9.])55(?![0-9.])", paragraph)
                          and re.search(r"(?<![0-9.])3(?![0-9.])", paragraph)]
                self.assertTrue(limits, "Preserve ASCII 55 total and 3 per-stage limits in one paragraph")

    def test_scanner_limits_are_present_in_all_languages(self):
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                paragraphs = re.split(r"\n\s*\n", document)
                self.assertTrue(any(all(re.search(r"(?<![0-9.])" + number + r"(?![0-9.])", part)
                                        for number in ("300", "600", "8")) for part in paragraphs))

    def test_no_developer_workstation_paths(self):
        workstation_paths = re.compile(
            r"/Users/|/home/[^/\s]+/|/Volumes/|/private/(?:tmp/|var/folders/)|"
            r"/mnt/data/|[A-Za-z]:[\\/]Users[\\/]", re.IGNORECASE)
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                self.assertIsNone(workstation_paths.search(document), "Developer workstation path leaked")

    def test_no_real_fleet_ip_addresses(self):
        for name, document in self.guides.items():
            for address in ip_literals(document):
                with self.subTest(guide=name, address=str(address)):
                    self.assertTrue(any(address in network for network in DOCUMENTATION_NETWORKS
                                        if network.version == address.version),
                                    "Use reserved documentation addresses, never actual fleet addresses")

    def test_no_external_script_download_commands(self):
        download_commands = re.compile(
            r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
            r"[^\n]*(?:https?://|ftp://)|"
            r"\b(?:urlretrieve|urlopen|requests\.get)\s*\([^\n]*(?:https?://|ftp://)",
            re.IGNORECASE)
        for name, document in self.guides.items():
            with self.subTest(guide=name):
                joined_lines = re.sub(r"\\\r?\n\s*", " ", document)
                self.assertIsNone(download_commands.search(joined_lines), "External script download command found")


if __name__ == "__main__":
    unittest.main()
