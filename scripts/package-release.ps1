[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$BinaryPath = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $repoRoot 'target\release\klens.exe'
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot 'dist'
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $cargoTomlPath = Join-Path $repoRoot 'Cargo.toml'
    if (-not (Test-Path $cargoTomlPath)) {
        throw "Cargo.toml not found at $cargoTomlPath"
    }
    $inWorkspacePackage = $false
    foreach ($line in Get-Content -Path $cargoTomlPath -Encoding UTF8) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '[workspace.package]') {
            $inWorkspacePackage = $true
            continue
        }
        if ($inWorkspacePackage -and $trimmed.StartsWith('[')) {
            break
        }
        if ($inWorkspacePackage -and $trimmed -match '^version\s*=\s*"([^"]+)"') {
            $Version = $Matches[1]
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Could not parse [workspace.package] version from $cargoTomlPath"
    }
}

$Version = $Version.TrimStart('v')

if (-not (Test-Path $BinaryPath)) {
    throw "Release binary not found at $BinaryPath. Run 'cargo build --release' first."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$artifactName = "klens-v$Version-windows-x86_64.exe"
$destBinary = Join-Path $OutDir $artifactName
Copy-Item -Path $BinaryPath -Destination $destBinary -Force

$hash = (Get-FileHash -Path $destBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$sumsPath = Join-Path $OutDir 'SHA256SUMS.txt'
$sumsContent = "$hash  $artifactName`n"

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($sumsPath, $sumsContent, $utf8NoBom)

# Fail-closed verification: ensure UTF-8 without BOM and pure LF (zero CR bytes).
$writtenBytes = [System.IO.File]::ReadAllBytes($sumsPath)
if ($writtenBytes.Length -ge 3 -and $writtenBytes[0] -eq 0xEF -and $writtenBytes[1] -eq 0xBB -and $writtenBytes[2] -eq 0xBF) {
    throw "SHA256SUMS.txt unexpectedly contains a UTF-8 BOM"
}
if ($writtenBytes -contains 0x0D) {
    throw "SHA256SUMS.txt unexpectedly contains CR (0x0D) bytes"
}

$sizeBytes = (Get-Item -Path $destBinary).Length
Write-Host "Packaged release artifact: $destBinary ($sizeBytes bytes)"
Write-Host "Generated pure-LF checksums: $sumsPath ($hash  $artifactName)"
