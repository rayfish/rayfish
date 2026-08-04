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
