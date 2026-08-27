<#
.SYNOPSIS
Rayfish installer for Windows. The counterpart to install.sh, which covers
Linux and macOS only and refuses to run here.

    irm https://rayfish.xyz/install.ps1 | iex

Options (environment variables, named to match install.sh):
    RAY_INSTALL_DIR   target dir (default: %ProgramFiles%\Rayfish)
    RAY_VERSION       pin a release tag, e.g. v0.1.0 (default: latest)
    RAY_SKIP_VERIFY   set to 1 to install without checksum verification

The two architectures install by different routes, because that is how they
are published:

  x64    gets the MSI, which is the supported installer. It registers the
         service, puts the directory on PATH and records the release identity
         `ray update` reads, so this script only downloads and runs it.

  ARM64  has no MSI (build-windows-msi.ps1 is x86_64 only, and pins the amd64
         Wintun), so it gets the bare ray.exe published beside it. This script
         does by hand what the MSI would do: place the binary, put the matching
         Wintun DLL next to it, and add the directory to PATH. Registering and
         starting the service is left to `ray install`, the same command the
         other platforms use.

This file is the canonical copy, as install.sh is of itself.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = 'rayfish/rayfish'
$installDir = if ($env:RAY_INSTALL_DIR) { $env:RAY_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'Rayfish' }
$version = if ($env:RAY_VERSION) { $env:RAY_VERSION } else { 'latest' }
$skipVerify = $env:RAY_SKIP_VERIFY -eq '1'

# Pinned Wintun, kept byte-identical to scripts/build-windows-msi.ps1, which is
# the source of truth: the MSI ships this exact build, so an ARM64 install that
# fetched a different one would put two Wintun versions in the wild.
$wintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
$wintunSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

function Write-Info { param([string]$Message) Write-Host $Message -ForegroundColor Blue }
function Write-Ok   { param([string]$Message) Write-Host $Message -ForegroundColor Green }

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this in an elevated PowerShell: it installs under Program Files and touches the system PATH.'
    }
}

# RuntimeInformation, not $env:PROCESSOR_ARCHITECTURE: a 32-bit PowerShell on
# ARM64 reports its own bitness there, and would install the wrong binary.
function Get-TargetArch {
    switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'Arm64' { 'arm64' }
        'X64'   { 'x64' }
        default {
            throw "unsupported architecture: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
        }
    }
}

function Get-ReleaseBase {
    if ($version -eq 'latest') {
        "https://github.com/$repo/releases/latest/download"
    } else {
        "https://github.com/$repo/releases/download/$version"
    }
}

# The published sidecar is `<digest>  <name>`; take the first field, as the
# in-binary updater does.
function Assert-Checksum {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Url
    )
    if ($skipVerify) {
        Write-Info '  skipping checksum verification (RAY_SKIP_VERIFY=1)'
        return
    }
    $sidecar = (Invoke-WebRequest -Uri "$Url.sha256" -UseBasicParsing).Content
    $expected = ($sidecar -split '\s+' | Where-Object { $_ })[0]
    if (-not $expected) { throw "no checksum published at $Url.sha256" }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpperInvariant()) {
        throw "checksum mismatch for $Url : expected $expected, got $($actual.ToLowerInvariant())"
    }
}

function Add-ToMachinePath {
    param([Parameter(Mandatory)][string]$Directory)
    $current = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = $current -split ';' | Where-Object { $_ }
    if ($entries -contains $Directory) {
        return
    }
    # Machine scope, matching the MSI: the install is per-machine, and the
    # service runs as LocalSystem.
    [Environment]::SetEnvironmentVariable('Path', ($current.TrimEnd(';') + ";$Directory"), 'Machine')
    Write-Info "  added $Directory to the system PATH (new shells only)"
}

function Install-Msi {
    param([Parameter(Mandatory)][string]$Workspace)
    $url = "$(Get-ReleaseBase)/ray-windows-x86_64.msi"
    $msi = Join-Path $Workspace 'ray-windows-x86_64.msi'
    Write-Info "Downloading $url..."
    Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
    Assert-Checksum -Path $msi -Url $url

    Write-Info 'Running the installer...'
    # /qn: the MSI is unattended by design, and this script is normally piped
    # into iex where there is nobody to click through a wizard.
    $process = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait -PassThru
    # 3010 is success-with-reboot-pending, not a failure.
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
        throw "msiexec failed with exit code $($process.ExitCode)."
    }
    Write-Ok 'Rayfish installed. The MSI registered and started the service.'
}

function Install-Arm64Binary {
    param([Parameter(Mandatory)][string]$Workspace)
    $url = "$(Get-ReleaseBase)/ray-windows-aarch64.exe"
    $exe = Join-Path $Workspace 'ray.exe'
    Write-Info "Downloading $url..."
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
    Assert-Checksum -Path $exe -Url $url

    # ray.exe loads wintun.dll from its own directory (src/tun.rs), so without
    # this the binary installs fine and then cannot create the tunnel.
    Write-Info 'Downloading Wintun...'
    $archive = Join-Path $Workspace 'wintun.zip'
    Invoke-WebRequest -Uri $wintunUrl -OutFile $archive -UseBasicParsing
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($archiveHash -ne $wintunSha256.ToUpperInvariant()) {
        throw "Wintun archive SHA-256 mismatch: expected $wintunSha256, got $($archiveHash.ToLowerInvariant())."
    }
    $extracted = Join-Path $Workspace 'wintun'
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted -Force
    $dll = Get-ChildItem -LiteralPath $extracted -Recurse -Filter 'wintun.dll' |
        Where-Object { $_.FullName -match '\\arm64\\wintun\.dll$' } |
        Select-Object -First 1
    if (-not $dll) { throw 'arm64/wintun.dll was not found in the pinned Wintun archive.' }
    $signature = Get-AuthenticodeSignature -FilePath $dll.FullName
    if ($signature.Status -ne 'Valid') {
        throw "Wintun Authenticode signature is not valid: $($signature.Status)."
    }

    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    }
    # Copy the DLL first: a ray.exe on PATH with no Wintun beside it is the one
    # half-installed state that looks fine until the first `ray up`.
    Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $installDir 'wintun.dll') -Force
    Copy-Item -LiteralPath $exe -Destination (Join-Path $installDir 'ray.exe') -Force
    Add-ToMachinePath -Directory $installDir

    Write-Ok "Rayfish installed to $installDir."
    Write-Host ''
    Write-Host 'The binary is unsigned: there is no ARM64 MSI yet, and signing is part of'
    Write-Host 'building one. Expect an unknown-publisher prompt from UAC and the firewall.'
    Write-Host ''
    Write-Host 'Next, in a new elevated shell, register and start the service:'
    Write-Host '    ray install'
}

Assert-Admin
$arch = Get-TargetArch
$workspace = Join-Path ([System.IO.Path]::GetTempPath()) "rayfish-install-$PID"
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
try {
    switch ($arch) {
        'x64'   { Install-Msi -Workspace $workspace }
        'arm64' { Install-Arm64Binary -Workspace $workspace }
    }
}
finally {
    Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
}
