# macOS releases

The **macOS app release** GitHub Actions workflow builds separate Apple Silicon
and Intel apps with Xcode 26.6. Each app contains the original Rust `ray` command
and the packet tunnel system extension. Both use the repository's Cargo version.
The DMG uses Rayfish's logo, fonts, and colors, with a drag-to-Applications layout.
Nightly releases do not run this workflow.

Configure these repository secrets before running it:

| Secret | Value |
| --- | --- |
| `MACOS_CERTIFICATE_P12` | Base64 of a Developer ID Application `.p12`, including its private key |
| `MACOS_CERTIFICATE_PASSWORD` | Password protecting that `.p12` |
| `MACOS_APP_PROFILE` | Base64 of the Developer ID distribution profile for `com.rayfish.app` |
| `MACOS_TUNNEL_PROFILE` | Base64 of the Developer ID distribution profile for `com.rayfish.app.tunnel` |
| `APPLE_API_PRIVATE_KEY` | Contents of an App Store Connect team API `.p8` key |
| `APPLE_API_KEY_ID` | That API key's ID |
| `APPLE_API_ISSUER_ID` | That API key's issuer ID |

The profiles must belong to team `3D9W8F63CL` and allow the capabilities in the
Release entitlements, including the packet tunnel system extension and app group.
Use Developer ID distribution profiles, not Apple Development profiles.
GitHub's [certificate setup guide](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications)
explains exporting and storing signing material. Keep secrets out of the repo.

Run the workflow manually on the branch to test production packaging. It uploads
the notarized DMGs and checksums as workflow artifacts without publishing a
release. A workflow must exist on the default branch before GitHub exposes its
manual Run workflow button.

The existing **Release** workflow calls it for version tags and manual releases.
The tag must match Cargo's version and point to the commit being built. Both
architectures must pass signing checks and Apple notarization before their DMGs
are attached to the existing release. Missing credentials or failed notarization
fail the job; there is no unsigned fallback. Other platform release jobs remain
independent.

Notarization first covers the app, then the final DMG. Tickets are stapled to both
so installation does not depend on fetching the ticket from Apple. Users drag
Rayfish into Applications and approve its network extension on first connection.
Build logs, submission IDs, and notarization reports are saved in the diagnostics
artifacts. A timeout stops publication; inspect that submission before retrying.

PR CI builds the app without signing secrets. Real VPN connection and extension
approval still need a Mac smoke test. Production builds use
`1000 + GITHUB_RUN_NUMBER` as their extension build number; Debug builds retain the
version in `project.yml`.

To preview the installer locally without submitting a release:

```sh
brew install create-dmg
bash scripts/package-macos-dmg.sh \
  target/macos-development/Build/Products/Debug/Rayfish.app \
  target/Rayfish-installer-preview.dmg
```

This preview contains the app passed to the script and is not a production release.
