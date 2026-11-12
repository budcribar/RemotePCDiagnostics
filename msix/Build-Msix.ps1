<#
.SYNOPSIS
  Stages and builds the Microsoft Store MSIX package (RemotePCDiagnostics-<Version>-win-x64.msix)
  for $0 Partner Center upload (Policy 10.2.9 compliant: asInvoker + allowElevation + zero .sys drivers).

.EXAMPLE
  pwsh -NoProfile -File msix/Build-Msix.ps1

.EXAMPLE
  pwsh -NoProfile -File msix/Build-Msix.ps1 -SkipPublish -IdentityName "12345BudCribar.RemotePCDiagnostics" -Publisher "CN=00000000-0000-0000-0000-000000000000"
#>
[CmdletBinding()]
param(
    [string] $Version = '',
    [string] $FourPartVersion = '',
    [string] $StageDir = '',
    [string] $MsixStageDir = '',
    [string] $OutputDir = '',
    [string] $IdentityName = '',
    [string] $Publisher = '',
    [string] $DisplayName = '',
    [string] $PublisherDisplayName = '',
    [string] $MakeAppxPath = '',
    [string] $RbwvSourceRoot = '',
    [switch] $UseRbwvSource,
    [switch] $SkipPublish,
    [switch] $SkipVerify,
    [switch] $StageOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$PropsFile = Join-Path $RepoRoot 'Directory.Build.props'

if ([string]::IsNullOrWhiteSpace($Version)) {
    [xml]$PropsXml = Get-Content -LiteralPath $PropsFile
    $Version = ($PropsXml.Project.PropertyGroup | ForEach-Object { $_['Version'] } | Where-Object { $_ } | Select-Object -First 1).InnerText.Trim()
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Could not determine <Version> from $PropsFile"
    }
}

# Microsoft Store MSIX Identity Version must be Major.Minor.Build.0 (each 0..65535, Revision = 0 for Partner Center).
if ([string]::IsNullOrWhiteSpace($FourPartVersion)) {
    $CoreVersion = ($Version -split '[-+]')[0]
    $Parts = @($CoreVersion -split '\.' | ForEach-Object {
        $n = 0
        if ([int]::TryParse($_, [ref]$n) -and $n -ge 0 -and $n -le 65535) { $n } else { 0 }
    })
    while ($Parts.Count -lt 3) { $Parts += 0 }
    $FourPartVersion = "$($Parts[0]).$($Parts[1]).$($Parts[2]).0"
}

if ($FourPartVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    throw "FourPartVersion '$FourPartVersion' must be a 4-part numeric version (Major.Minor.Build.Revision)."
}

if ([string]::IsNullOrWhiteSpace($IdentityName)) {
    $IdentityName = if ($env:MSIX_IDENTITY_NAME) { $env:MSIX_IDENTITY_NAME.Trim() } else { 'BudCribar.RemotePCDiagnostics' }
}
if ([string]::IsNullOrWhiteSpace($Publisher)) {
    $Publisher = if ($env:MSIX_PUBLISHER) { $env:MSIX_PUBLISHER.Trim() } else { 'CN=BudCribar' }
}
if ([string]::IsNullOrWhiteSpace($DisplayName)) {
    $DisplayName = if ($env:MSIX_DISPLAY_NAME) { $env:MSIX_DISPLAY_NAME.Trim() } else { 'Remote PC Diagnostics' }
}
if ([string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    $PublisherDisplayName = if ($env:MSIX_PUBLISHER_DISPLAY_NAME) { $env:MSIX_PUBLISHER_DISPLAY_NAME.Trim() } else { 'Bud Cribar' }
}

if ([string]::IsNullOrWhiteSpace($StageDir)) {
    $StageDir = Join-Path $RepoRoot 'artifacts/installer-stage'
}
if ([string]::IsNullOrWhiteSpace($MsixStageDir)) {
    $MsixStageDir = Join-Path $RepoRoot 'artifacts/msix-stage'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot 'artifacts/msix'
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# 1) Verify source app.manifest Store Policy 10.2.9 compliance up front.
$HostManifestPath = Join-Path $RepoRoot 'src/RemotePCDiagnostics.Host/app.manifest'
$HostManifestText = Get-Content -LiteralPath $HostManifestPath -Raw
if ($HostManifestText -match 'requireAdministrator') {
    throw "Store Policy 10.2.9 violation: $HostManifestPath still contains requireAdministrator."
}
if ($HostManifestText -notmatch 'level="asInvoker"') {
    throw "Store Policy 10.2.9 violation: $HostManifestPath must declare level=`"asInvoker`"."
}

# 2) Stage published self-contained win-x64 application layout unless -SkipPublish was supplied.
if (-not $SkipPublish) {
    $BuildInstaller = Join-Path $RepoRoot 'installer/Build-Installer.ps1'
    $StageParams = @{
        Version    = $Version
        StageDir   = $StageDir
        OutputDir  = $OutputDir
        StageOnly  = $true
        SkipVerify = $SkipVerify.IsPresent
    }
    if (-not [string]::IsNullOrWhiteSpace($RbwvSourceRoot)) { $StageParams['RbwvSourceRoot'] = $RbwvSourceRoot }
    if ($UseRbwvSource.IsPresent)                           { $StageParams['UseRbwvSource'] = $true }

    & $BuildInstaller @StageParams
}

if (-not (Test-Path -LiteralPath $StageDir)) {
    throw "Published stage directory does not exist: $StageDir. Run without -SkipPublish or run installer/Build-Installer.ps1 -StageOnly first."
}

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

# 3) Assert ZERO .sys kernel drivers exist anywhere in the staged directory (Store Policy 10.2.9).
$SysDrivers = @(Get-ChildItem -LiteralPath $StageDir -Recurse -Filter '*.sys' -ErrorAction SilentlyContinue)
if ($SysDrivers.Count -gt 0) {
    $DriverPaths = ($SysDrivers | ForEach-Object { $_.FullName }) -join ', '
    throw "Store Policy 10.2.9 violation: MSIX layout must contain zero .sys kernel drivers, found $($SysDrivers.Count): $DriverPaths"
}

# 4) Verify required executables and ensure embedded Win32 manifests do not request requireAdministrator.
foreach ($ExeRel in @('RemotePCDiagnostics.Host.exe', 'RemotePCDiagnostics.Admin.exe', 'RemotePCDiagnostics.MemTest.exe', 'RemotePCDiagnostics.ModuleHost.exe', 'moduleui/RemotePCDiagnostics.ModuleUiHost.exe')) {
    $ExeFull = Join-Path $StageDir $ExeRel
    if (-not (Test-Path -LiteralPath $ExeFull)) {
        throw "Required executable missing from staged folder: $ExeFull"
    }
}

foreach ($CheckExe in @('RemotePCDiagnostics.Host.exe', 'RemotePCDiagnostics.Admin.exe')) {
    $ExeBytes = [System.IO.File]::ReadAllBytes((Join-Path $StageDir $CheckExe))
    $ExeAscii = [System.Text.Encoding]::ASCII.GetString($ExeBytes)
    if ($ExeAscii.Contains('level="requireAdministrator"')) {
        throw "Store Policy 10.2.9 violation: compiled $CheckExe embeds level=`"requireAdministrator`" in its Win32 manifest."
    }
}

# 5) Validate MSIX visual PNG assets (signature + exact dimensions).
$AssetsSourceDir = Join-Path $PSScriptRoot 'Assets'
$ExpectedAssets = @(
    @{ Name = 'Square44x44Logo.png';   Width = 44;  Height = 44  }
    @{ Name = 'StoreLogo.png';         Width = 50;  Height = 50  }
    @{ Name = 'Square150x150Logo.png'; Width = 150; Height = 150 }
    @{ Name = 'Wide310x150Logo.png';   Width = 310; Height = 150 }
)

foreach ($Asset in $ExpectedAssets) {
    $AssetPath = Join-Path $AssetsSourceDir $Asset.Name
    if (-not (Test-Path -LiteralPath $AssetPath)) {
        throw "Missing MSIX visual asset: $AssetPath"
    }
    $Bytes = [System.IO.File]::ReadAllBytes($AssetPath)
    if ($Bytes.Length -lt 24 -or $Bytes[0] -ne 0x89 -or $Bytes[1] -ne 0x50 -or $Bytes[2] -ne 0x4E -or $Bytes[3] -ne 0x47) {
        throw "Invalid PNG header in MSIX asset: $AssetPath"
    }
    $Width  = ([int]$Bytes[16] -shl 24) -bor ([int]$Bytes[17] -shl 16) -bor ([int]$Bytes[18] -shl 8) -bor [int]$Bytes[19]
    $Height = ([int]$Bytes[20] -shl 24) -bor ([int]$Bytes[21] -shl 16) -bor ([int]$Bytes[22] -shl 8) -bor [int]$Bytes[23]
    if ($Width -ne $Asset.Width -or $Height -ne $Asset.Height) {
        throw "MSIX asset $($Asset.Name) has dimensions ${Width}x${Height}, expected $($Asset.Width)x$($Asset.Height)."
    }
}

# 6) Populate clean MSIX staging directory (application files + Assets + rendered AppxManifest.xml).
if (Test-Path -LiteralPath $MsixStageDir) {
    Remove-Item -LiteralPath $MsixStageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $MsixStageDir | Out-Null
$MsixStageDir = (Resolve-Path -LiteralPath $MsixStageDir).Path

Copy-Item -Path (Join-Path $StageDir '*') -Destination $MsixStageDir -Recurse -Force

# Strip debug symbols (.pdb) and double-check zero .sys files in MSIX stage.
Get-ChildItem -LiteralPath $MsixStageDir -Recurse -Filter '*.pdb' -ErrorAction SilentlyContinue | Remove-Item -Force
$MsixSysDrivers = @(Get-ChildItem -LiteralPath $MsixStageDir -Recurse -Filter '*.sys' -ErrorAction SilentlyContinue)
if ($MsixSysDrivers.Count -gt 0) {
    throw "MSIX stage unexpectedly contains .sys driver files."
}

$MsixAssetsDest = Join-Path $MsixStageDir 'Assets'
New-Item -ItemType Directory -Force -Path $MsixAssetsDest | Out-Null
Copy-Item -Path (Join-Path $AssetsSourceDir '*.png') -Destination $MsixAssetsDest -Force

function Escape-XmlAttribute {
    param([string] $Value)
    return [System.Security.SecurityElement]::Escape($Value)
}

$TemplatePath = Join-Path $PSScriptRoot 'AppxManifest.template.xml'
$ManifestContent = Get-Content -LiteralPath $TemplatePath -Raw
$ManifestContent = $ManifestContent.Replace('{{IDENTITY_NAME}}', (Escape-XmlAttribute $IdentityName))
$ManifestContent = $ManifestContent.Replace('{{PUBLISHER}}', (Escape-XmlAttribute $Publisher))
$ManifestContent = $ManifestContent.Replace('{{FOUR_PART_VERSION}}', (Escape-XmlAttribute $FourPartVersion))
$ManifestContent = $ManifestContent.Replace('{{DISPLAY_NAME}}', (Escape-XmlAttribute $DisplayName))
$ManifestContent = $ManifestContent.Replace('{{PUBLISHER_DISPLAY_NAME}}', (Escape-XmlAttribute $PublisherDisplayName))

# Validate well-formed XML before writing UTF-8 without BOM.
$null = [xml]$ManifestContent
$AppxManifestOut = Join-Path $MsixStageDir 'AppxManifest.xml'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($AppxManifestOut, $ManifestContent, $Utf8NoBom)

Write-Host "Prepared MSIX stage at '$MsixStageDir' (Identity='$IdentityName', Version='$FourPartVersion', zero .sys files)." -ForegroundColor Green

if ($StageOnly) {
    Write-Host "StageOnly requested; skipping MakeAppx.exe packaging." -ForegroundColor Green
    return
}

function Find-MakeAppxExecutable {
    param([string] $ExplicitPath)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "Specified MakeAppx.exe was not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $Cmd = Get-Command 'makeappx.exe' -ErrorAction SilentlyContinue
    if (-not $Cmd) { $Cmd = Get-Command 'makeappx' -ErrorAction SilentlyContinue }
    if ($Cmd -and $Cmd.Source) { return $Cmd.Source }

    $KitRoots = @()
    if (${env:ProgramFiles(x86)}) { $KitRoots += Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin' }
    if ($env:ProgramFiles)        { $KitRoots += Join-Path $env:ProgramFiles 'Windows Kits\10\bin' }

    foreach ($Root in $KitRoots) {
        if (Test-Path -LiteralPath $Root) {
            $Found = Get-ChildItem -LiteralPath $Root -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'x64\makeappx.exe' } |
                Where-Object { Test-Path -LiteralPath $_ } |
                Select-Object -First 1
            if ($Found) {
                return (Resolve-Path -LiteralPath $Found).Path
            }
        }
    }

    throw "Windows SDK MakeAppx.exe was not found. Install the Windows 10/11 SDK or pass -MakeAppxPath <path>."
}

$MakeAppx = Find-MakeAppxExecutable -ExplicitPath $MakeAppxPath
$MsixFileName = "RemotePCDiagnostics-$Version-win-x64.msix"
$MsixPath = Join-Path $OutputDir $MsixFileName
if (Test-Path -LiteralPath $MsixPath) {
    Remove-Item -LiteralPath $MsixPath -Force
}

Write-Host "Packing MSIX with MakeAppx ($MakeAppx) ..." -ForegroundColor Cyan
& $MakeAppx pack /d $MsixStageDir /p $MsixPath /o
if ($LASTEXITCODE -ne 0) {
    throw "MakeAppx.exe pack failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath $MsixPath)) {
    throw "Expected MSIX package was not created: $MsixPath"
}

$MsixSizeBytes = (Get-Item -LiteralPath $MsixPath).Length
if ($MsixSizeBytes -lt 20MB) {
    throw "MSIX package is unexpectedly small ($MsixSizeBytes bytes); expected self-contained win-x64 bundle."
}

$Hash = (Get-FileHash -LiteralPath $MsixPath -Algorithm SHA256).Hash.ToLowerInvariant()
$ShaFile = "$MsixPath.sha256"
[System.IO.File]::WriteAllText($ShaFile, "$Hash  $MsixFileName", $Utf8NoBom)

$SizeMb = [Math]::Round($MsixSizeBytes / 1MB, 2)
Write-Host ""
Write-Host "Microsoft Store MSIX package built successfully:" -ForegroundColor Green
Write-Host "  File:     $MsixPath ($SizeMb MB)"
Write-Host "  Identity: $IdentityName ($Publisher) v$FourPartVersion"
Write-Host "  SHA256:   $Hash"
Write-Host "  Hash:     $ShaFile"
Write-Host '  Note:     Upload directly to Microsoft Partner Center for $0 Store signing (no local EV cert required).'
