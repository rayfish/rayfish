# Windows packaging

The Windows runtime uses the signed Wintun 0.14.1 driver DLL. Keep the DLL
outside source control (the vendor archive is redistributable under its own
license) and place `wintun.dll` at `packaging/windows/wintun/amd64/wintun.dll`
before building an MSI.

Expected upstream artifact:

- URL: <https://www.wintun.net/builds/wintun-0.14.1.zip>
- SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`

Run `scripts/verify-wintun.ps1 -Path <dll> -ArchivePath <zip>` to check both the
archive digest and Authenticode signature. The MSI step is intentionally gated
on this verification.
