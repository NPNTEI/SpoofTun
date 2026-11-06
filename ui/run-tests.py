#!/usr/bin/env python3
"""Run every UI test, including compatibility; skipped tests are not a pass."""
from pathlib import Path
import sys
import unittest

root = Path(__file__).resolve().parent
if not (root.parent / "packaging" / "tunnel-doctor.py").is_file():
    raise SystemExit("Full compatibility tests need the complete GitHub source, with ui/ beside packaging/.")
suite = unittest.defaultTestLoader.discover(str(root), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != 79 or result.skipped:
    raise SystemExit("Incomplete validation: expected 79 tests and zero skips.")
sys.exit(0 if result.wasSuccessful() else 1)
