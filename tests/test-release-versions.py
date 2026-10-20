#!/usr/bin/env python3
"""Regression tests for the cargo-release app version hook."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import runpy
import tempfile
import unittest


update_versions = runpy.run_path(
    str(Path(__file__).resolve().parent.parent / "scripts/update-release-versions.py")
)["update_versions"]


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = self.root / "macos/project.yml"
        self.project = self.root / "macos/Rayfish.xcodeproj/project.pbxproj"
        for app in ("macos", "ios"):
            (self.root / app / "Rayfish.xcodeproj").mkdir(parents=True)
            (self.root / app / "project.yml").write_text(
                '    MARKETING_VERSION: "1.2.3"\n    CURRENT_PROJECT_VERSION: "7"\n'
            )
            (self.root / app / "Rayfish.xcodeproj/project.pbxproj").write_text(
                '\tMARKETING_VERSION = 1.2.3;\n' * 3
            )
        output = redirect_stdout(StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_updates_every_configuration_and_preserves_build_number(self):
        update_versions(self.root, "2.0.0")
        self.assertEqual(
            self.spec.read_text(),
            '    MARKETING_VERSION: "2.0.0"\n    CURRENT_PROJECT_VERSION: "7"\n',
        )
        self.assertEqual(self.project.read_text(), '\tMARKETING_VERSION = 2.0.0;\n' * 3)
        ios = self.root / "ios/Rayfish.xcodeproj/project.pbxproj"
        self.assertEqual(ios.read_text(), '\tMARKETING_VERSION = 2.0.0;\n' * 3)

    def test_prerelease_and_metadata_remain_numeric_for_apple(self):
        update_versions(self.root, "2.0.0-rc.1+build.2")
        self.assertIn('MARKETING_VERSION: "2.0.0"', self.spec.read_text())
        self.assertEqual(self.project.read_text(), '\tMARKETING_VERSION = 2.0.0;\n' * 3)

    def test_dry_run_changes_no_files(self):
        original = self.spec.read_text(), self.project.read_text()
        update_versions(self.root, "2.0.0", dry_run=True)
        self.assertEqual(original, (self.spec.read_text(), self.project.read_text()))

    def test_missing_field_fails_before_writing_other_files(self):
        original = self.spec.read_text()
        self.project.write_text("// No version field\n")
        with self.assertRaisesRegex(ValueError, "No MARKETING_VERSION"):
            update_versions(self.root, "2.0.0")
        self.assertEqual(original, self.spec.read_text())

    def test_invalid_version_fails_before_writing(self):
        original = self.spec.read_text()
        with self.assertRaisesRegex(ValueError, "Invalid release version"):
            update_versions(self.root, "invalid")
        self.assertEqual(original, self.spec.read_text())


if __name__ == "__main__":
    unittest.main()
