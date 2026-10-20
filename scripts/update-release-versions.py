#!/usr/bin/env python3
"""Update app version fields before cargo-release creates its release commit."""

import argparse
import os
from pathlib import Path
import re


def update_versions(root: Path, version: str, dry_run: bool = False) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError(f"Invalid release version: {version}")
    marketing_version = re.split(r"[-+]", version, maxsplit=1)[0]
    fields = {
        "macos/project.yml": r'(MARKETING_VERSION: ")[^"]+("[ \t]*$)',
        "macos/Rayfish.xcodeproj/project.pbxproj": r"(MARKETING_VERSION = )[^;]+(;[ \t]*$)",
        "ios/project.yml": r'(MARKETING_VERSION: ")[^"]+("[ \t]*$)',
        "ios/Rayfish.xcodeproj/project.pbxproj": r"(MARKETING_VERSION = )[^;]+(;[ \t]*$)",
    }
    updates = {}
    for name, pattern in fields.items():
        path = root / name
        original = path.read_text()
        updated, count = re.subn(
            pattern,
            lambda match: match[1] + marketing_version + match[2],
            original,
            flags=re.MULTILINE,
        )
        if count == 0:
            raise ValueError(f"No MARKETING_VERSION field in {name}")
        if updated != original:
            updates[path] = updated

    for path, updated in updates.items():
        print(f"{path.relative_to(root)}: {marketing_version}")
        if not dry_run:
            path.write_text(updated)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="New Cargo package version")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        update_versions(
            Path(__file__).resolve().parent.parent,
            args.version,
            args.dry_run or os.environ.get("DRY_RUN") == "true",
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
