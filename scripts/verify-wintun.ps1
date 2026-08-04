[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path,
    [Parameter(Mandatory = $false)]
    [string]$ArchivePath
)

$expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
if (-not $Path -and -not $ArchivePath) {
    $Path = Join-Path $PSScriptRoot '..\packaging\windows\wintun\amd64\wintun.dll'
}
$resolved = $null
if ($Path) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
}
if ($ArchivePath) {
    $archive = (Resolve-Path -LiteralPath $ArchivePath -ErrorAction Stop).Path
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Wintun archive SHA-256 mismatch: expected $expected, got $actual"
    }
    $archiveRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rayfish-wintun-verify-$PID"
    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $archiveRoot -Force
        $archiveDll = Get-ChildItem -LiteralPath $archiveRoot -Recurse -Filter 'wintun.dll' |
            Where-Object { $_.FullName -match '\\amd64\\wintun\.dll$' } |
            Select-Object -First 1
        if (-not $archiveDll) {
            throw 'amd64/wintun.dll was not found in the verified Wintun archive.'
        }
        if ($resolved) {
            $archiveDllHash = (Get-FileHash -LiteralPath $archiveDll.FullName -Algorithm SHA256).Hash
            $resolvedHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
            if ($archiveDllHash -ne $resolvedHash) {
                throw 'The supplied Wintun DLL does not match amd64/wintun.dll from the verified archive.'
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $archiveRoot) {
            Remove-Item -LiteralPath $archiveRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($resolved) {
    $signature = Get-AuthenticodeSignature -FilePath $resolved
    if ($signature.Status -ne 'Valid') {
        throw "Wintun Authenticode signature is not valid: $($signature.Status)"
    }
}

if ($resolved) {
    Write-Output "Wintun verified: $resolved"
}
elseif ($ArchivePath) {
    Write-Output "Wintun archive verified: $archive"
}
