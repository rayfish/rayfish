#!/usr/bin/env python3
"""Check the release notes used by the publishing workflows."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import changelog


HISTORY = """# Changelog

## [1.2.2] - 2026-01-01

### Fixed

- Earlier fix.

[1.2.2]: https://example.com/releases/tag/v1.2.2
"""


class ChangelogTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.history = self.root / "CHANGELOG.md"
        self.history.write_text(HISTORY)
        self.pending = self.root / "changelogs/unreleased"
        self.pending.mkdir(parents=True)

    def fragment(self, name, body):
        path = self.pending / name
        path.write_text(body)
        return path

    def test_preview_and_freeze_two_independent_fragments(self):
        second = self.fragment("20-second.md", "### Fixed\n\n- Second fix.\n")
        first = self.fragment(
            "10-first.md", "### Fixed\n\n- First fix.\n  More detail.\n\n### Added\n\n- A feature.\n"
        )
        expected = "### Added\n\n- A feature.\n\n### Fixed\n\n- First fix.\n  More detail.\n- Second fix."

        self.assertEqual(changelog.pending(changelog.fragments(self.root)), expected)
        self.assertEqual(self.history.read_text(), HISTORY)

        changelog.freeze(self.root, "1.2.3")

        self.assertEqual(changelog.notes(self.root, "1.2.3"), expected)
        self.assertEqual(changelog.notes(self.root, "1.2.2"), "### Fixed\n\n- Earlier fix.")
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        self.assertEqual(changelog.pending(changelog.fragments(self.root)), "")

    def test_invalid_fragment_leaves_history_and_fragments_untouched(self):
        valid = self.fragment("10-valid.md", "### Fixed\n\n- A fix.\n")
        invalid = self.fragment("20-invalid.md", "### Other\n\n- A change.\n")
        with self.assertRaisesRegex(ValueError, "unknown section"):
            changelog.freeze(self.root, "1.2.3")
        self.assertEqual(self.history.read_text(), HISTORY)
        self.assertTrue(valid.exists())
        self.assertTrue(invalid.exists())

    def test_cannot_freeze_empty_or_duplicate_release(self):
        with self.assertRaisesRegex(ValueError, "No pending release notes"):
            changelog.freeze(self.root, "1.2.3")
        with self.assertRaisesRegex(ValueError, "already exist"):
            changelog.freeze(self.root, "1.2.2")
        with self.assertRaisesRegex(ValueError, "Missing or duplicate release notes"):
            changelog.notes(self.root, "1.2.3")
        self.assertEqual(self.history.read_text(), HISTORY)

    def test_rejects_legacy_unreleased_section(self):
        self.history.write_text(HISTORY.replace("## [1.2.2]", "## [Unreleased]"))
        with self.assertRaisesRegex(ValueError, "move Unreleased entries"):
            changelog.history(self.root)


if __name__ == "__main__":
    unittest.main()
