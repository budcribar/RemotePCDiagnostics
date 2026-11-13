<#
.SYNOPSIS
  Compiles the standalone Windows Installer package (RemotePCDiagnostics.Agent-<Version>-win-x64.msi)
  for the Remote PC Diagnostics Windows Service Agent using WiX Toolset v5 (WixToolset.Sdk).

.EXAMPLE
  pwsh -NoProfile -File msi/Build-AgentMsi.ps1

.EXAMPLE
  pwsh -NoProfile -File msi/Build-AgentMsi.ps1 -SkipPublish -AgentExePath artifacts/agent/RemotePCDiagnostics.Agent-1.2.0-win-x64.exe
#>
[CmdletBinding()]
param(
    [string] $Version = '',
    [string] $AgentExePath = '',
    [string] $OutputDir = '',
    [switch] $SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$IsWindowsHost = ($env:OS -eq 'Windows_NT') -or ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
if (-not $IsWindowsHost) {
    throw 'WiX Toolset v5 MSI compilation requires a Windows build host.'
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$PropsFile = Join-Path $RepoRoot 'Directory.Build.props'

if ([string]::IsNullOrWhiteSpace($Version)) {
    [xml]$PropsXml = Get-Content -LiteralPath $PropsFile
    $Version = ($PropsXml.Project.PropertyGroup | ForEach-Object { $_['Version'] } | Where-Object { $_ } | Select-Object -First 1).InnerText.Trim()
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Could not determine <Version> from $PropsFile"
    }
}

# Windows Installer ProductVersion uses Major.Minor.Build (0..255.0..255.0..65535).
$CoreVersion = ($Version -split '[-+]')[0]
$Parts = @($CoreVersion -split '\.' | ForEach-Object {
    $n = 0
    if ([int]::TryParse($_, [ref]$n) -and $n -ge 0) { $n } else { 0 }
})
while ($Parts.Count -lt 3) { $Parts += 0 }
$Major = [Math]::Min(255, $Parts[0])
$Minor = [Math]::Min(255, $Parts[1])
$Build = [Math]::Min(65535, $Parts[2])
$NumericVersion = "$Major.$Minor.$Build"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot 'artifacts/agent'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

# Ensure the local NuGet feed folder referenced by NuGet.Config exists on fresh clones.
$LocalNuGetDir = Join-Path $RepoRoot 'third_party/RemoteBlazorWebView/packages'
New-Item -ItemType Directory -Force -Path $LocalNuGetDir | Out-Null

if (-not $SkipPublish -and [string]::IsNullOrWhiteSpace($AgentExePath)) {
    $PubDir = Join-Path $RepoRoot 'artifacts/agent-stage'
    if (Test-Path -LiteralPath $PubDir) {
        Remove-Item -LiteralPath $PubDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $PubDir | Out-Null

    Write-Host "Publishing RemotePCDiagnostics.Agent $Version (win-x64 single-file self-contained) ..." -ForegroundColor Cyan
    & dotnet publish (Join-Path $RepoRoot 'src/RemotePCDiagnostics.Agent/RemotePCDiagnostics.Agent.csproj') `
        -c Release `
        -r win-x64 `
        --self-contained `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None `
        "-p:Version=$Version" `
        -o $PubDir
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish for RemotePCDiagnostics.Agent failed with exit code $LASTEXITCODE."
    }
    $AgentExePath = Join-Path $PubDir 'RemotePCDiagnostics.Agent.exe'
}

if ([string]::IsNullOrWhiteSpace($AgentExePath) -or -not (Test-Path -LiteralPath $AgentExePath)) {
    throw "Agent executable was not found: '$AgentExePath'."
}
$AgentExePath = (Resolve-Path -LiteralPath $AgentExePath).Path

$WixStageOut = Join-Path $RepoRoot 'artifacts/agent-msi-stage'
if (Test-Path -LiteralPath $WixStageOut) {
    Remove-Item -LiteralPath $WixStageOut -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $WixStageOut | Out-Null

$MsiBaseName = "RemotePCDiagnostics.Agent-$Version-win-x64"
$MsiFileName = "$MsiBaseName.msi"
$WixProj = Join-Path $PSScriptRoot 'RemotePCDiagnostics.Agent.Msi.wixproj'
$IconPath = (Resolve-Path -LiteralPath (Join-Path $RepoRoot 'src/RemotePCDiagnostics.Host/Assets/diagnostics.ico')).Path

Write-Host "Building MSI package $MsiFileName (ProductVersion=$NumericVersion) ..." -ForegroundColor Cyan
& dotnet build $WixProj `
    -c Release `
    "-p:AppNumericVersion=$NumericVersion" `
    "-p:AgentExePath=$AgentExePath" `
    "-p:IconPath=$IconPath" `
    "-p:MsiOutputName=$MsiBaseName" `
    -o $WixStageOut
if ($LASTEXITCODE -ne 0) {
    throw "WiX MSI build failed with exit code $LASTEXITCODE."
}

$BuiltMsi = Get-ChildItem -LiteralPath $WixStageOut -Recurse -Filter $MsiFileName -File | Select-Object -First 1
if ($null -eq $BuiltMsi) {
    throw "Expected WiX MSI output '$MsiFileName' was not found under '$WixStageOut'."
}

$DestMsi = Join-Path $OutputDir $MsiFileName
Copy-Item -LiteralPath $BuiltMsi.FullName -Destination $DestMsi -Force

$MsiSizeBytes = (Get-Item -LiteralPath $DestMsi).Length
if ($MsiSizeBytes -lt 5MB) {
    throw "MSI package '$DestMsi' is unexpectedly small ($MsiSizeBytes bytes); expected embedded self-contained win-x64 agent."
}

$Hash = (Get-FileHash -LiteralPath $DestMsi -Algorithm SHA256).Hash.ToLowerInvariant()
$ShaFile = "$DestMsi.sha256"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ShaFile, "$Hash  $MsiFileName", $Utf8NoBom)

$SizeMb = [Math]::Round($MsiSizeBytes / 1MB, 2)
Write-Host ""
Write-Host "Agent MSI built successfully:" -ForegroundColor Green
Write-Host "  File:   $DestMsi ($SizeMb MB)"
Write-Host "  SHA256: $Hash"
Write-Host "  Hash:   $ShaFile"
