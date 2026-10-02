#!/usr/bin/env python3
"""Write a one-release Sparkle feed for a notarized macOS disk image."""

import argparse
import base64
import plistlib
import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree


SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ElementTree.register_namespace("sparkle", SPARKLE_NS)


def release_notes(changelog: Path, version: str) -> str:
    text = changelog.read_text()
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None or not match.group(1).strip():
        raise ValueError(f"release notes for {version} are missing")
    return match.group(1).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sign-update", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--dmg", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--arch", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        parser.error("tag must be a stable version such as v1.2.3")
    expected_name = f"Rayfish-{args.tag[1:]}-{args.arch}.dmg"
    if args.dmg.name != expected_name:
        parser.error(f"disk image must be named {expected_name}")

    with (args.app / "Contents/Info.plist").open("rb") as source:
        info = plistlib.load(source)
    build = info.get("CFBundleVersion", "")
    if not build.isdecimal() or info.get("CFBundleShortVersionString") != args.tag[1:]:
        raise ValueError("app version does not match the release")
    feed = f"https://github.com/rayfish/rayfish/releases/latest/download/Rayfish-appcast-{args.arch}.xml"
    if info.get("SUFeedURL") != feed:
        raise ValueError("app update feed does not match the architecture")

    seed = base64.b64decode(args.key.read_text().strip(), validate=True)
    if len(seed) != 32:
        raise ValueError("Sparkle private key must be a 32-byte Ed25519 seed")
    private_der = bytes.fromhex("302e020100300506032b657004220420") + seed
    public_der = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private_der,
        capture_output=True,
        check=True,
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")
    if not public_der.startswith(prefix) or len(public_der) != len(prefix) + 32:
        raise ValueError("could not derive the Sparkle public key")
    public_key = base64.b64encode(public_der[len(prefix):]).decode()
    if info.get("SUPublicEDKey") != public_key:
        raise ValueError("Sparkle signing key does not match the app")

    signed = subprocess.run(
        [str(args.sign_update), "-f", str(args.key), str(args.dmg)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    match = re.search(r'sparkle:edSignature="([A-Za-z0-9+/=]+)" length="([0-9]+)"', signed)
    if match is None or int(match.group(2)) != args.dmg.stat().st_size:
        raise ValueError("Sparkle signature or archive length is invalid")

    root = ElementTree.Element("rss", {"version": "2.0"})
    channel = ElementTree.SubElement(root, "channel")
    ElementTree.SubElement(channel, "title").text = "Rayfish updates"
    item = ElementTree.SubElement(channel, "item")
    ElementTree.SubElement(item, "title").text = f"Rayfish {args.tag[1:]}"
    ElementTree.SubElement(item, "description", {f"{{{SPARKLE_NS}}}format": "markdown"}).text = release_notes(
        args.changelog, args.tag[1:]
    )
    ElementTree.SubElement(item, f"{{{SPARKLE_NS}}}version").text = build
    ElementTree.SubElement(item, f"{{{SPARKLE_NS}}}shortVersionString").text = args.tag[1:]
    ElementTree.SubElement(item, f"{{{SPARKLE_NS}}}minimumSystemVersion").text = "13.0"
    ElementTree.SubElement(
        item,
        "enclosure",
        {
            "url": f"https://github.com/rayfish/rayfish/releases/download/{args.tag}/{expected_name}",
            f"{{{SPARKLE_NS}}}edSignature": match.group(1),
            "length": match.group(2),
            "type": "application/octet-stream",
        },
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    ElementTree.ElementTree(root).write(args.output, encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
