# Windows packaging

The Windows runtime uses the signed Wintun 0.14.1 driver DLL. The shared builder
downloads the pinned archive into the system temp directory, verifies its SHA-256
and Authenticode signature, stages the DLL beside the release binary, then removes
all staging data.

Build locally (WiX 3.14.1 and cargo-wix 0.3.9 must be installed):

```powershell
./scripts/build-windows-msi.ps1 -Version 0.2.1
```

Outputs are `ray-windows-x86_64.msi`, `.sha256`, and `.version`. No Wintun DLL is
checked into source control.

Expected upstream artifact:

- URL: <https://www.wintun.net/builds/wintun-0.14.1.zip>
- SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`

Run `scripts/verify-wintun.ps1 -ArchivePath <zip>` for archive-only validation,
or pass `-Path <dll>` as well to validate Authenticode.

## Signing

Tagged releases are Authenticode signed through SignPath. Pull request artifacts
are not: fork workflows cannot read repository secrets, so `windows.yml` always
produces an unsigned MSI.

Two things have to be signed, and only signing the MSI is not enough. An
unsigned `ray.exe` inside a signed package still shows an unknown publisher on
every UAC prompt, firewall dialog and service start after the install. SignPath's
artifact configuration handles both in one pass: it signs the executable nested
inside the MSI, then the MSI itself.

The `.sha256` sidecar is written after signing, never before. Signing rewrites the
file, so a hash taken at build time describes something nobody will download.
That is why `write-msi-sidecars.ps1` is a separate script: the release workflow
runs it again on the file that comes back signed.

`release.yml` needs one secret, `SIGNPATH_API_TOKEN`, plus four repository
variables from the SignPath portal: `SIGNPATH_ORGANIZATION_ID`,
`SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG` and
`SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`. With the secret unset the signing steps
skip and the release publishes unsigned assets.

For a key reachable from the build machine (a cloud HSM through signtool, or a
test certificate) the builder signs in place instead:

```powershell
./scripts/build-windows-msi.ps1 -Version 0.3.0 `
    -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' `
    -SignArgs sign,/fd,sha256,/sha1,<thumbprint>,/tr,http://timestamp.digicert.com,/td,sha256,'{file}'
```

`{file}` is replaced with each file being signed. Always pass a timestamp URL:
without one, every signature stops validating the day the certificate expires.

While the mesh is active, Windows NRPT also routes each configured network name
as a match domain (alongside the `.ray` search domains). Existing NRPT rules and
DNS suffixes outside Rayfish ownership are preserved and restored on shutdown.
