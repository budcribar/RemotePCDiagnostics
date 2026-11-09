<#
.SYNOPSIS
  Publishes Remote PC Diagnostics (multi-file self-contained win-x64) and compiles the
  Inno Setup Windows installer (RemotePCDiagnostics-Setup-<Version>-win-x64.exe).

.EXAMPLE
  pwsh -NoProfile -File installer/Build-Installer.ps1

.EXAMPLE
  pwsh -NoProfile -File installer/Build-Installer.ps1 -Version 1.2.1
#>
[CmdletBinding()]
param(
    [string] $Version = '',
    [string] $StageDir = '',
    [string] $OutputDir = '',
    [string] $IsccPath = '',
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

# Build a 4-part numeric version (X.Y.Z.W) for Inno Setup's VersionInfoVersion even if $Version has a prerelease label.
$CoreVersion = ($Version -split '[-+]')[0]
$VersionParts = @($CoreVersion -split '\.' | ForEach-Object {
    $n = 0
    if ([int]::TryParse($_, [ref]$n)) { $n } else { 0 }
})
while ($VersionParts.Count -lt 4) { $VersionParts += 0 }
$NumericVersion = ($VersionParts[0..3] -join '.')

if ([string]::IsNullOrWhiteSpace($StageDir)) {
    $StageDir = Join-Path $RepoRoot 'artifacts/installer-stage'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot 'artifacts/installer'
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Ensure the local NuGet feed folder referenced by NuGet.Config exists on fresh clones.
$LocalNuGetDir = Join-Path $RepoRoot 'third_party/RemoteBlazorWebView/packages'
New-Item -ItemType Directory -Force -Path $LocalNuGetDir | Out-Null

if ([string]::IsNullOrWhiteSpace($RbwvSourceRoot)) {
    $RbwvSourceRoot = Join-Path (Split-Path -Parent $RepoRoot) 'RemoteBlazorWebView'
}

$HasLocalRbwvPackages = @(Get-ChildItem -LiteralPath $LocalNuGetDir -Filter 'PeakSWC.RemoteBlazorWebView.Wpf.*.nupkg' -ErrorAction SilentlyContinue).Count -gt 0
$HasSiblingRbwvSource = Test-Path -LiteralPath (Join-Path $RbwvSourceRoot 'src/RemoteBlazorWebView.Wpf/RemoteBlazorWebView.Wpf.csproj')

$BuildFromRbwvSource = $UseRbwvSource.IsPresent -or ((-not $HasLocalRbwvPackages) -and $HasSiblingRbwvSource)

if (-not $SkipPublish) {
    if (Test-Path -LiteralPath $StageDir) {
        Remove-Item -LiteralPath $StageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

    $PublishArgs = @(
        'publish'
        (Join-Path $RepoRoot 'src/RemotePCDiagnostics.Host/RemotePCDiagnostics.Host.csproj')
        '-c', 'Release'
        '-r', 'win-x64'
        '--self-contained', 'true'
        '-p:PublishProfile=Installer'
        '-p:GeneratePackageOnBuild=false'
        "-p:Version=$Version"
    )

    $RunningOnWindows = ($env:OS -eq 'Windows_NT') -or ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
    if (-not $RunningOnWindows) {
        $PublishArgs += '-p:EnableWindowsTargeting=true'
    }

    if ($BuildFromRbwvSource) {
        $ResolvedRbwv = (Resolve-Path -LiteralPath $RbwvSourceRoot).Path
        $JsBundle = Join-Path $ResolvedRbwv 'src/RemoteWebView.Blazor.JS/dist/remote.blazor.desktop.js'
        if (-not (Test-Path -LiteralPath $JsBundle)) {
            $JsProjectDir = Join-Path $ResolvedRbwv 'src/RemoteWebView.Blazor.JS'
            Write-Host "Building RemoteBlazorWebView JS bundle in $JsProjectDir ..." -ForegroundColor Cyan
            Push-Location $JsProjectDir
            try {
                & npm install --no-audit --no-fund
                if ($LASTEXITCODE -ne 0) { throw "npm install failed in $JsProjectDir ($LASTEXITCODE)" }
                & npm run build:production
                if ($LASTEXITCODE -ne 0) { throw "npm run build:production failed in $JsProjectDir ($LASTEXITCODE)" }
            }
            finally {
                Pop-Location
            }
        }
        Write-Host "Publishing Remote PC Diagnostics $Version using sibling RemoteBlazorWebView source ($ResolvedRbwv) ..." -ForegroundColor Cyan
        $PublishArgs += '-p:UseRbwvSource=true'
        $PublishArgs += "-p:RbwvSourceRoot=$ResolvedRbwv"
    }
    else {
        Write-Host "Publishing Remote PC Diagnostics $Version (win-x64 self-contained) ..." -ForegroundColor Cyan
    }

    $PublishArgs += @('-o', $StageDir)

    & dotnet @PublishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed with exit code $LASTEXITCODE"
    }
}

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

# Validate staged file layout (runs on both Windows and non-Windows build hosts).
$RequiredFiles = @(
    'RemotePCDiagnostics.Host.exe'
    'RemotePCDiagnostics.MemTest.exe'
    'RemotePCDiagnostics.MemTest.runtimeconfig.json'
    'RemotePCDiagnostics.ModuleHost.exe'
    'RemotePCDiagnostics.ModuleHost.runtimeconfig.json'
    'moduleui/RemotePCDiagnostics.ModuleUiHost.exe'
    'moduleui/RemotePCDiagnostics.ModuleUiHost.runtimeconfig.json'
    'moduleui/wwwroot/index.html'
    'moduleui/wwwroot/app.css'
    'tools/osquery/osqueryi.exe'
    'tools/HardeningKitty/HardeningKitty.psd1'
    'tools/HardeningKitty/HardeningKitty.psm1'
    'wwwroot/index.html'
)

$Missing = @($RequiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $StageDir $_)) })
if ($Missing.Count -gt 0) {
    throw "Staged publish folder '$StageDir' is missing required files: $($Missing -join ', ')"
}

$ModuleDlls = @(Get-ChildItem -LiteralPath (Join-Path $StageDir 'builtin-modules') -Filter '*.dll' -ErrorAction SilentlyContinue)
if ($ModuleDlls.Count -lt 24) {
    throw "Expected at least 24 bundled module DLLs in '$StageDir/builtin-modules', found $($ModuleDlls.Count)."
}
Write-Host "Verified staged layout: $($ModuleDlls.Count) bundled modules + Host, MemTest, ModuleHost, and ModuleUiHost." -ForegroundColor Green

$IsWindowsHost = ($env:OS -eq 'Windows_NT') -or ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
if ($IsWindowsHost -and -not $SkipVerify) {
    $HostExe = Join-Path $StageDir 'RemotePCDiagnostics.Host.exe'
    $VerifyLog = Join-Path $OutputDir 'verify-package.log'
    Remove-Item -LiteralPath $VerifyLog -Force -ErrorAction SilentlyContinue

    Write-Host "Running RemotePCDiagnostics.Host.exe --verify-package ..." -ForegroundColor Cyan
    $PrevLog = $env:RPD_LOG_FILE
    $env:RPD_LOG_FILE = $VerifyLog
    try {
        $Proc = Start-Process -FilePath $HostExe -ArgumentList '--verify-package' -WorkingDirectory $StageDir -WindowStyle Hidden -PassThru
        if (-not $Proc.WaitForExit(60000)) {
            Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
            throw 'RemotePCDiagnostics.Host.exe --verify-package timed out after 60 seconds.'
        }
        if ($Proc.ExitCode -ne 0) {
            if (Test-Path -LiteralPath $VerifyLog) { Get-Content -LiteralPath $VerifyLog | Write-Host }
            throw "RemotePCDiagnostics.Host.exe --verify-package failed with exit code $($Proc.ExitCode)."
        }
    }
    finally {
        $env:RPD_LOG_FILE = $PrevLog
    }
    Write-Host "Package self-verification passed." -ForegroundColor Green
}

if ($StageOnly) {
    Write-Host "StageOnly requested; skipping Inno Setup compilation. Staged files are at: $StageDir" -ForegroundColor Green
    return
}

function Find-IsccExecutable {
    param([string] $ExplicitPath)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "Specified ISCC.exe was not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $Cmd = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if (-not $Cmd) { $Cmd = Get-Command 'iscc' -ErrorAction SilentlyContinue }
    if ($Cmd -and $Cmd.Source) { return $Cmd.Source }

    $Candidates = @()
    if (${env:ProgramFiles(x86)}) { $Candidates += Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }
    if ($env:ProgramFiles)        { $Candidates += Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe' }
    if ($env:LOCALAPPDATA)        { $Candidates += Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' }

    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    throw "Inno Setup 6 compiler (ISCC.exe) was not found. Install Inno Setup 6 via 'winget install --id JRSoftware.InnoSetup -e' or 'choco install innosetup -y', or pass -IsccPath <path>."
}

$Iscc = Find-IsccExecutable -ExplicitPath $IsccPath
$IssFile = Join-Path $PSScriptRoot 'RemotePCDiagnostics.iss'

Write-Host "Compiling installer with Inno Setup ($Iscc) ..." -ForegroundColor Cyan
& $Iscc `
    "/DAppVersion=$Version" `
    "/DAppNumericVersion=$NumericVersion" `
    "/DRepoRoot=$RepoRoot" `
    "/DPublishDir=$StageDir" `
    "/DOutputDir=$OutputDir" `
    $IssFile

if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
}

$SetupFileName = "RemotePCDiagnostics-Setup-$Version-win-x64.exe"
$SetupExePath = Join-Path $OutputDir $SetupFileName
if (-not (Test-Path -LiteralPath $SetupExePath)) {
    throw "Expected installer output was not created: $SetupExePath"
}

$Hash = (Get-FileHash -LiteralPath $SetupExePath -Algorithm SHA256).Hash.ToLowerInvariant()
$ShaFile = "$SetupExePath.sha256"
Set-Content -LiteralPath $ShaFile -Value "$Hash  $SetupFileName" -NoNewline -Encoding ascii

$SizeMb = [Math]::Round((Get-Item -LiteralPath $SetupExePath).Length / 1MB, 2)
Write-Host ""
Write-Host "Installer built successfully:" -ForegroundColor Green
Write-Host "  File:   $SetupExePath ($SizeMb MB)"
Write-Host "  SHA256: $Hash"
Write-Host "  Hash:   $ShaFile"
