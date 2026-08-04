[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string]$ReleaseIdentity = $Version,

    [Parameter(Mandatory = $false)]
    [ValidateSet('stable', 'nightly')]
    [string]$Channel = 'stable',

    [Parameter(Mandatory = $false)]
    [ValidateSet('x86_64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Get-Location) 'target\ray-windows-x86_64.msi')
)

$ErrorActionPreference = 'Stop'

$wintunVersion = '0.14.1'
$wintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
$wintunSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Enable-WixToolset {
    if ((Get-Command 'candle.exe' -ErrorAction SilentlyContinue) -and
        (Get-Command 'light.exe' -ErrorAction SilentlyContinue)) {
        return
    }

    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3.14\bin'),
        (Join-Path $env:ProgramFiles 'WiX Toolset v3.14\bin')
    )
    $wixBin = $candidates | Where-Object {
        (Test-Path (Join-Path $_ 'candle.exe')) -and (Test-Path (Join-Path $_ 'light.exe'))
    } | Select-Object -First 1
    if (-not $wixBin) {
        throw "WiX Toolset 3.14 was not found in PATH or its standard install directories."
    }
    $env:PATH = "$wixBin;$env:PATH"
}

function Assert-MsiVersion {
    param([Parameter(Mandatory = $true)][string]$Value)
    $parts = $Value.Split('.') | ForEach-Object { [int]$_ }
    if ($parts.Count -ne 3 -or $parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
        throw "MSI ProductVersion '$Value' must be major.minor.build with major/minor in 0..255 and build in 0..65535."
    }
}

Assert-Command 'cargo'
Enable-WixToolset
Assert-MsiVersion $Version

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targetBinDir = Join-Path $repoRoot "target\$Target\release"
$output = [System.IO.Path]::GetFullPath($OutputPath)
$outputDir = Split-Path -Parent $output
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rayfish-windows-msi-$PID"
$archive = Join-Path $tempRoot "wintun-$wintunVersion.zip"
$extractRoot = Join-Path $tempRoot 'wintun'
$msiBinDir = Join-Path $tempRoot 'bin'
$stagedDll = Join-Path $msiBinDir 'wintun.dll'

New-Item -ItemType Directory -Force -Path $tempRoot, $outputDir | Out-Null

try {
    Write-Host "Building ray for $Target..."
    Push-Location $repoRoot
    try {
        & cargo build --release --locked --target $Target --features desktop --bin ray
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    Write-Host "Downloading Wintun $wintunVersion..."
    Invoke-WebRequest -Uri $wintunUrl -OutFile $archive -UseBasicParsing
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($archiveHash -ne $wintunSha256.ToLowerInvariant()) {
        throw "Wintun archive SHA-256 mismatch: expected $wintunSha256, got $archiveHash."
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force
    $dll = Get-ChildItem -LiteralPath $extractRoot -Recurse -Filter 'wintun.dll' |
        Where-Object { $_.FullName -match '\\amd64\\wintun\.dll$' } |
        Select-Object -First 1
    if (-not $dll) {
        throw 'amd64/wintun.dll was not found in the pinned Wintun archive.'
    }
    $signature = Get-AuthenticodeSignature -FilePath $dll.FullName
    if ($signature.Status -ne 'Valid') {
        throw "Wintun Authenticode signature is not valid: $($signature.Status)."
    }

    New-Item -ItemType Directory -Force -Path $msiBinDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $targetBinDir 'ray.exe') -Destination (Join-Path $msiBinDir 'ray.exe') -Force
    Copy-Item -LiteralPath $dll.FullName -Destination $stagedDll -Force

    Write-Host "Building MSI ProductVersion $Version ($Channel identity $ReleaseIdentity)..."
    Push-Location $repoRoot
    try {
        $wixArgs = @(
            'wix', '-p', 'rayfish', '--no-build',
            '--target', $Target,
            '--target-bin-dir', $msiBinDir,
            '--install-version', $Version,
            '--compiler-arg', "-dProductVersion=$Version",
            '--compiler-arg', "-dReleaseIdentity=$ReleaseIdentity",
            '--compiler-arg', "-dReleaseChannel=$Channel",
            '--output', $output
        )
        & cargo @wixArgs
        if ($LASTEXITCODE -ne 0) {
            throw "cargo wix failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
        throw "cargo wix completed without producing $output."
    }
    $msiHash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    $msiName = Split-Path -Leaf $output
    Set-Content -LiteralPath "$output.sha256" -Value "$msiHash  $msiName" -Encoding ascii
    Set-Content -LiteralPath "$output.version" -Value $ReleaseIdentity -Encoding ascii
    Write-Output "MSI: $output"
    Write-Output "SHA256: $output.sha256"
    Write-Output "VERSION: $output.version"
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
