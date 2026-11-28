<#
.SYNOPSIS
  Publishes Remote PC Diagnostics (multi-file self-contained win-x64) and compiles the
  Inno Setup Windows installer (RemotePCDiagnostics-Setup-<Version>-win-x64.exe).

.EXAMPLE
  pwsh -NoProfile -File installer/Build-Installer.ps1

.EXAMPLE
  pwsh -NoProfile -File installer/Build-Installer.ps1 -PublishPreRelease
#>
[CmdletBinding()]
param(
    [string] $Version = '',
    [ValidateSet('win-x64', 'win-arm64')]
    [string] $Rid = 'win-x64',
    # Store builds the Microsoft Store edition (-p:RpcdEdition=Store): it also ships the no-Agent readers and osquery. Stage only (the MSIX).
    [ValidateSet('Setup', 'Store')]
    [string] $Edition = 'Setup',
    [string] $StageDir = '',
    [string] $OutputDir = '',
    [string] $OutputBaseName = '',
    [string] $RemoteServerUrl = '',
    [string] $ShopGroup = '',
    [string] $AgentExePath = '',
    [string] $AgentMsiPath = '',
    [string] $AgentServerUrl = '',
    [string] $AgentEnrollmentKey = '',
    [string] $AgentConsent = '',
    [string] $IsccPath = '',
    [string] $Compression = '',
    [string] $RbwvSourceRoot = '',
    [switch] $UseRbwvSource,
    [switch] $SkipPublish,
    [switch] $NoReadyToRun,
    [switch] $SkipVerify,
    [switch] $StageOnly,
    [switch] $PublishPreRelease
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

if ($Edition -eq 'Store' -and -not $StageOnly) {
    throw "The Store edition is only staged for the MSIX (msix/Build-Msix.ps1); add -StageOnly."
}
if ([string]::IsNullOrWhiteSpace($StageDir)) {
    $StageDir = if ($Rid -eq 'win-x64') {
        Join-Path $RepoRoot 'artifacts/installer-stage'
    } else {
        Join-Path $RepoRoot "artifacts/installer-stage-$Rid"
    }
    if ($Edition -eq 'Store') { $StageDir += '-store' }
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
        '-r', $Rid
        '--self-contained', 'true'
        '-p:PublishProfile=Installer'
        '-p:GeneratePackageOnBuild=false'
        '-p:UseSharedCompilation=false'
        '-nodeReuse:false'
        "-p:Version=$Version"
    )
    if ($Edition -eq 'Store') {
        $PublishArgs += '-p:RpcdEdition=Store'
    }
    # Faster publish for development builds (CI TestShop-only runs); the app starts a little slower without ReadyToRun.
    if ($NoReadyToRun) {
        $PublishArgs += '-p:PublishReadyToRun=false'
    }

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
        Write-Host "Publishing Remote PC Diagnostics $Version ($Rid) using sibling RemoteBlazorWebView source ($ResolvedRbwv) ..." -ForegroundColor Cyan
        $PublishArgs += '-p:UseRbwvSource=true'
        $PublishArgs += "-p:RbwvSourceRoot=$ResolvedRbwv"
    }
    else {
        Write-Host "Publishing Remote PC Diagnostics $Version ($Rid self-contained) ..." -ForegroundColor Cyan
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
    'RemotePCDiagnostics.Agent.exe'
    'RemotePCDiagnostics.Agent.runtimeconfig.json'
    'RemotePCDiagnostics.Agent.deps.json'
    'RemotePCDiagnostics.MemTest.exe'
    'RemotePCDiagnostics.MemTest.runtimeconfig.json'
    'RemotePCDiagnostics.MemTest.deps.json'
    'RemotePCDiagnostics.ModuleHost.exe'
    'RemotePCDiagnostics.ModuleHost.runtimeconfig.json'
    'RemotePCDiagnostics.ModuleHost.deps.json'
    'moduleui/RemotePCDiagnostics.ModuleUiHost.exe'
    'moduleui/RemotePCDiagnostics.ModuleUiHost.runtimeconfig.json'
    'moduleui/RemotePCDiagnostics.ModuleUiHost.deps.json'
    'moduleui/wwwroot/index.html'
    'moduleui/wwwroot/app.css'
    'tools/HardeningKitty/HardeningKitty.psd1'
    'tools/HardeningKitty/HardeningKitty.psm1'
    'benchmarks/speedometer-3.1.zip'
    'media/playback-test-1080p30.mp4'
    'wwwroot/index.html'
)

# The Store edition reads without the Agent through the legacy readers, which need the bundled osquery.
if ($Edition -eq 'Store') {
    $RequiredFiles += 'tools/osquery/osqueryi.exe'
    $RequiredFiles += 'RemotePCDiagnostics.Legacy.dll'
}

$Missing = @($RequiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $StageDir $_)) })
if ($Missing.Count -gt 0) {
    throw "Staged publish folder '$StageDir' is missing required files: $($Missing -join ', ')"
}

$ModuleDlls = @(Get-ChildItem -LiteralPath (Join-Path $StageDir 'builtin-modules') -Filter '*.dll' -ErrorAction SilentlyContinue)
if ($ModuleDlls.Count -lt 24) {
    throw "Expected at least 24 bundled module DLLs in '$StageDir/builtin-modules', found $($ModuleDlls.Count)."
}
Write-Host "Verified staged layout: $($ModuleDlls.Count) bundled modules + Host, Agent, MemTest, ModuleHost, and ModuleUiHost." -ForegroundColor Green

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

if ([string]::IsNullOrWhiteSpace($OutputBaseName)) {
    $OutputBaseName = "RemotePCDiagnostics-Setup-$Version-$Rid"
}

$IsccArgs = @(
    "/DAppVersion=$Version"
    "/DAppNumericVersion=$NumericVersion"
    "/DRepoRoot=$RepoRoot"
    "/DPublishDir=$StageDir"
    "/DOutputDir=$OutputDir"
    "/DOutputBaseName=$OutputBaseName"
    "/DRid=$Rid"
)

if (-not [string]::IsNullOrWhiteSpace($RemoteServerUrl)) {
    $IsccArgs += "/DRemoteServerUrl=$RemoteServerUrl"
}
if (-not [string]::IsNullOrWhiteSpace($ShopGroup)) {
    $IsccArgs += "/DShopGroup=$ShopGroup"
}
if (-not [string]::IsNullOrWhiteSpace($AgentExePath) -and -not [string]::IsNullOrWhiteSpace($AgentMsiPath)) {
    throw "Pass -AgentExePath or -AgentMsiPath, not both. The TestShop bundle installs the agent exe. The regular Setup embeds the Agent MSI."
}
if (-not [string]::IsNullOrWhiteSpace($AgentExePath)) {
    if (-not (Test-Path -LiteralPath $AgentExePath)) {
        throw "Specified AgentExePath was not found: $AgentExePath"
    }
    $ResolvedAgentExe = (Resolve-Path -LiteralPath $AgentExePath).Path
    $IsccArgs += "/DAgentExePath=$ResolvedAgentExe"
}
if (-not [string]::IsNullOrWhiteSpace($AgentMsiPath)) {
    if (-not (Test-Path -LiteralPath $AgentMsiPath)) {
        throw "Specified AgentMsiPath was not found: $AgentMsiPath"
    }
    $ResolvedAgentMsi = (Resolve-Path -LiteralPath $AgentMsiPath).Path
    $IsccArgs += "/DAgentMsiPath=$ResolvedAgentMsi"
}
if (-not [string]::IsNullOrWhiteSpace($AgentServerUrl)) {
    $IsccArgs += "/DAgentServerUrl=$AgentServerUrl"
}
if (-not [string]::IsNullOrWhiteSpace($AgentEnrollmentKey)) {
    $IsccArgs += "/DAgentEnrollmentKey=$AgentEnrollmentKey"
}
if (-not [string]::IsNullOrWhiteSpace($AgentConsent)) {
    $IsccArgs += "/DAgentConsent=$AgentConsent"
}
if (-not [string]::IsNullOrWhiteSpace($Compression)) {
    $IsccArgs += "/DCompression=$Compression"
}

$IsccArgs += $IssFile

Write-Host "Compiling installer '$OutputBaseName.exe' with Inno Setup ($Iscc) ..." -ForegroundColor Cyan
& $Iscc @IsccArgs

if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
}

$SetupFileName = "$OutputBaseName.exe"
$SetupExePath = Join-Path $OutputDir $SetupFileName
if (-not (Test-Path -LiteralPath $SetupExePath)) {
    throw "Expected installer output was not created: $SetupExePath"
}

# Signed before hashing so the .sha256 describes the published (signed) Setup. A no-op without signing secrets.
& (Join-Path $PSScriptRoot 'Sign-ReleaseFile.ps1') -Path $SetupExePath

$Hash = (Get-FileHash -LiteralPath $SetupExePath -Algorithm SHA256).Hash.ToLowerInvariant()
$ShaFile = "$SetupExePath.sha256"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ShaFile, "$Hash  $SetupFileName", $Utf8NoBom)

$SizeMb = [Math]::Round((Get-Item -LiteralPath $SetupExePath).Length / 1MB, 2)
Write-Host ""
Write-Host "Installer built successfully:" -ForegroundColor Green
Write-Host "  File:   $SetupExePath ($SizeMb MB)"
Write-Host "  SHA256: $Hash"
Write-Host "  Hash:   $ShaFile"

if ($PublishPreRelease) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI ('gh') is required for -PublishPreRelease. Install via 'winget install --id GitHub.cli -e' and sign in with 'gh auth login'."
    }
    Push-Location $RepoRoot
    try {
        $CommitSha = (& git rev-parse HEAD).Trim()
        $ShortSha = $CommitSha.Substring(0, [Math]::Min(7, $CommitSha.Length))

        Write-Host ""
        Write-Host "Removing previous pre-releases so only one copy is kept ..." -ForegroundColor Cyan
        $OldTagsJson = (& gh release list --limit 50 --json tagName,isPrerelease) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "gh release list failed ($LASTEXITCODE)" }
        $ParsedReleases = if ([string]::IsNullOrWhiteSpace($OldTagsJson)) { @() } else { @($OldTagsJson | ConvertFrom-Json) }
        $OldTags = @(foreach ($Rel in $ParsedReleases) {
            if ($null -ne $Rel -and ($Rel.isPrerelease -or $Rel.tagName -eq 'prerelease')) {
                $Rel.tagName
            }
        })
        foreach ($OldTag in $OldTags) {
            if ($OldTag) {
                Write-Host "  Deleting $OldTag ..."
                & gh release delete $OldTag --cleanup-tag --yes | Out-Null
            }
        }

        Write-Host "Creating rolling pre-release 'prerelease' ($ShortSha) ..." -ForegroundColor Cyan
        & gh release create 'prerelease' $SetupExePath $ShaFile `
            --prerelease `
            --target $CommitSha `
            --title "Remote PC Diagnostics $Version ($ShortSha)" `
            --notes "Rolling pre-release built from commit $CommitSha."
        if ($LASTEXITCODE -ne 0) { throw "gh release create failed ($LASTEXITCODE)" }
        Write-Host "Rolling pre-release published." -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}
