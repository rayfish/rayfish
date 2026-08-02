[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = (Join-Path $PSScriptRoot '..\packaging\windows\wintun\amd64\wintun.dll'),
    [Parameter(Mandatory = $false)]
    [string]$ArchivePath
)

$expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if ($ArchivePath) {
    $archive = (Resolve-Path -LiteralPath $ArchivePath -ErrorAction Stop).Path
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Wintun archive SHA-256 mismatch: expected $expected, got $actual"
    }
}

$signature = Get-AuthenticodeSignature -FilePath $resolved
if ($signature.Status -ne 'Valid') {
    throw "Wintun Authenticode signature is not valid: $($signature.Status)"
}

Write-Output "Wintun verified: $resolved"
