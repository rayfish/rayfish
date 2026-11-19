#!/usr/bin/env python3
"""Validate, render, or freeze Rayfish's pending changelog fragments."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
RELEASE = re.compile(
    r"^## \[([^]\n]+)\][^\n]*\n(.*?)(?=^## |^\[[0-9][^]\n]+\]: |\Z)",
    re.MULTILINE | re.DOTALL,
)
SUBSECTION = re.compile(r"^### ([^\n]+)\n", re.MULTILINE)
SECTIONS = ("Added", "Changed", "Fixed", "Security", "Performance")


def read_fragment(path: Path) -> dict[str, str]:
    parts = SUBSECTION.split(path.read_text(encoding="utf-8"))
    if parts[0].strip() or len(parts) == 1:
        raise ValueError(f"{path}: start with a ### section")

    sections = {}
    for name, body in zip(parts[1::2], parts[2::2]):
        if name not in SECTIONS:
            raise ValueError(f"{path}: unknown section {name!r}, expected {', '.join(SECTIONS)}")
        if name in sections:
            raise ValueError(f"{path}: duplicate section {name}")

        body = body.strip()
        if not re.match(r"- \S", body):
            raise ValueError(f"{path}: section {name} needs a Markdown list")
        if re.search(r"(?m)^#", body):
            raise ValueError(f"{path}: unexpected heading in section {name}")
        sections[name] = body

    return sections


def fragments(root: Path) -> list[Path]:
    return sorted((root / "changelogs/unreleased").glob("*.md"))


def history(root: Path) -> str:
    path = root / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^## \[Unreleased\]", text):
        raise ValueError(f"{path}: move Unreleased entries to changelogs/unreleased/")
    return text


def pending(paths: list[Path]) -> str:
    collected = {name: [] for name in SECTIONS}
    for path in paths:
        for name, body in read_fragment(path).items():
            collected[name].append(body)

    return "\n\n".join(
        f"### {name}\n\n" + "\n".join(items)
        for name, items in collected.items()
        if items
    )


def notes(root: Path, version: str) -> str:
    matches = [
        body.strip() for name, body in RELEASE.findall(history(root)) if name == version
    ]
    if len(matches) != 1 or not re.search(r"(?m)^- \S", matches[0]):
        raise ValueError(f"Missing or duplicate release notes for {version}")
    return matches[0]


def freeze(root: Path, version: str) -> None:
    if not VERSION.fullmatch(version):
        raise ValueError("Expected a stable version such as 1.2.3")

    text = history(root)
    if any(name == version for name, _ in RELEASE.findall(text)):
        raise ValueError(f"Release notes already exist for {version}")

    paths = fragments(root)
    body = pending(paths)
    if not body:
        raise ValueError("No pending release notes in changelogs/unreleased/")

    date = datetime.now(timezone.utc).date().isoformat()
    entry = f"## [{version}] - {date}\n\n{body}\n\n"
    first = RELEASE.search(text)
    if first:
        text = text[:first.start()] + entry + text[first.start():]
    else:
        text = text.rstrip() + "\n\n" + entry

    base = "https://github.com/rayfish/rayfish"
    link = f"[{version}]: {base}/releases/tag/v{version}\n"
    references = re.search(r"(?m)^\[[0-9][^]\n]+\]: ", text)
    if references:
        text = text[:references.start()] + link + text[references.start():]
    else:
        text = text.rstrip() + "\n\n" + link

    (root / "CHANGELOG.md").write_text(text, encoding="utf-8")
    for path in paths:
        path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="Validate pending fragments and the changelog")
    preview = commands.add_parser("pending", help="Print the pending release notes")
    preview.add_argument("--require-entries", action="store_true")
    for command in ("notes", "freeze"):
        commands.add_parser(command).add_argument("version")
    args = parser.parse_args()

    try:
        if args.command in ("check", "pending"):
            history(ROOT)
            body = pending(fragments(ROOT))
            if args.command == "pending":
                if args.require_entries and not body:
                    raise ValueError("No pending release notes in changelogs/unreleased/")
                if body:
                    print(body)
        elif args.command == "freeze":
            freeze(ROOT, args.version)
        else:
            print(notes(ROOT, args.version))
    except (OSError, ValueError) as error:
        parser.exit(1, f"changelog: {error}\n")


if __name__ == "__main__":
    main()
