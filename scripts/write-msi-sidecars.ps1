[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string]$ReleaseIdentity
)

# The `.sha256` and `.version` files that ship next to the MSI. Separate from
# build-windows-msi.ps1 because signing can happen after the build: SignPath
# takes the artifact and returns a signed one, which changes the bytes, so the
# release workflow runs this again on the file that actually gets published.
# Writing the hash once, at build time, would publish a hash of the unsigned
# MSI and every verification a user runs would fail.

$ErrorActionPreference = 'Stop'

$path = [System.IO.Path]::GetFullPath($MsiPath)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "No MSI at '$path'."
}

$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
$name = Split-Path -Leaf $path

# Two spaces between hash and name: the format sha256sum -c expects, so the
# Linux and Windows assets on a release are checked the same way.
Set-Content -LiteralPath "$path.sha256" -Value "$hash  $name" -Encoding ascii
Set-Content -LiteralPath "$path.version" -Value $ReleaseIdentity -Encoding ascii

Write-Output "SHA256: $path.sha256 ($hash)"
Write-Output "VERSION: $path.version ($ReleaseIdentity)"
