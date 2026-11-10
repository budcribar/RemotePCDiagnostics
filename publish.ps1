<#
.SYNOPSIS
  Builds the Remote PC Diagnostics Inno Setup installer and publishes it as the
  single rolling GitHub pre-release ('prerelease'), replacing any previous pre-release.

.EXAMPLE
  .\publish.ps1

.EXAMPLE
  .\publish.ps1 -LocalOnly

.EXAMPLE
  .\publish.ps1 -IncludePortable
#>
[CmdletBinding()]
param(
    [string] $Version = '',
    [string] $IsccPath = '',
    [string] $RbwvSourceRoot = '',
    [switch] $UseRbwvSource,
    [switch] $IncludePortable,
    [switch] $SkipVerify,
    [switch] $LocalOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot
$PropsFile = Join-Path $RepoRoot 'Directory.Build.props'

if ([string]::IsNullOrWhiteSpace($Version)) {
    [xml]$PropsXml = Get-Content -LiteralPath $PropsFile
    $Version = ($PropsXml.Project.PropertyGroup | ForEach-Object { $_['Version'] } | Where-Object { $_ } | Select-Object -First 1).InnerText.Trim()
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Could not determine <Version> from $PropsFile"
    }
}

# 1) Stop running app processes so output assemblies aren't locked.
Get-Process RemotePCDiagnostics.Host, RemotePCDiagnostics.ModuleHost, RemotePCDiagnostics.ModuleUiHost -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Host "Stopping running process $($_.ProcessName) ($($_.Id)) ..." -ForegroundColor Yellow
        $_ | Stop-Process -Force
    }

# 2) Check GitHub CLI authentication up front (unless -LocalOnly) so we fail fast before a multi-minute build.
if (-not $LocalOnly) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI ('gh') was not found. Install via 'winget install --id GitHub.cli -e' and sign in with 'gh auth login', or pass -LocalOnly."
    }
    & gh auth status *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI is not signed in. Run 'gh auth login' first, or pass -LocalOnly."
    }
}

# 3) Ensure Inno Setup 6 (ISCC.exe) is available, auto-installing via winget on Windows if missing.
function Resolve-OrInstallIscc {
    param([string] $Explicit)
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "Specified ISCC.exe not found: $Explicit" }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }

    $Candidates = @()
    $Cmd = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if ($Cmd -and $Cmd.Source) { $Candidates += $Cmd.Source }
    if (${env:ProgramFiles(x86)}) { $Candidates += Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }
    if ($env:ProgramFiles)        { $Candidates += Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe' }
    if ($env:LOCALAPPDATA)        { $Candidates += Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' }

    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Inno Setup 6 not found - installing JRSoftware.InnoSetup via winget ..." -ForegroundColor Cyan
        & winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
        foreach ($c in @(
            $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }),
            $(if ($env:ProgramFiles)        { Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe' }),
            $(if ($env:LOCALAPPDATA)        { Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' })
        )) {
            if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
        }
    }

    throw "Inno Setup 6 (ISCC.exe) was not found. Install via 'winget install --id JRSoftware.InnoSetup -e' or pass -IsccPath <path>."
}

$ResolvedIscc = Resolve-OrInstallIscc -Explicit $IsccPath

# 4) Build the Inno Setup installer (artifacts/installer/RemotePCDiagnostics-Setup-<Version>-win-x64.exe).
$OutputDir = Join-Path $RepoRoot 'artifacts/installer'
$BuildInstallerScript = Join-Path $RepoRoot 'installer/Build-Installer.ps1'

$InstallerParams = @{
    Version    = $Version
    OutputDir  = $OutputDir
    IsccPath   = $ResolvedIscc
    SkipVerify = $SkipVerify.IsPresent
}
if (-not [string]::IsNullOrWhiteSpace($RbwvSourceRoot)) { $InstallerParams['RbwvSourceRoot'] = $RbwvSourceRoot }
if ($UseRbwvSource.IsPresent)                           { $InstallerParams['UseRbwvSource'] = $true }

& $BuildInstallerScript @InstallerParams

$SetupFileName = "RemotePCDiagnostics-Setup-$Version-win-x64.exe"
$SetupExePath  = Join-Path $OutputDir $SetupFileName
$SetupShaPath  = "$SetupExePath.sha256"

$ReleaseAssets = @($SetupExePath, $SetupShaPath)

# 5) Only build the single-file Portable executable when -IncludePortable is explicitly passed.
if ($IncludePortable) {
    $LocalNuGetDir = Join-Path $RepoRoot 'third_party/RemoteBlazorWebView/packages'
    New-Item -ItemType Directory -Force -Path $LocalNuGetDir | Out-Null

    $EffectiveRbwvRoot = if ([string]::IsNullOrWhiteSpace($RbwvSourceRoot)) {
        Join-Path (Split-Path -Parent $RepoRoot) 'RemoteBlazorWebView'
    } else {
        $RbwvSourceRoot
    }
    $HasLocalRbwvPackages = @(Get-ChildItem -LiteralPath $LocalNuGetDir -Filter 'PeakSWC.RemoteBlazorWebView.Wpf.*.nupkg' -ErrorAction SilentlyContinue).Count -gt 0
    $HasSiblingRbwvSource = Test-Path -LiteralPath (Join-Path $EffectiveRbwvRoot 'src/RemoteBlazorWebView.Wpf/RemoteBlazorWebView.Wpf.csproj')
    $BuildFromRbwvSource  = $UseRbwvSource.IsPresent -or ((-not $HasLocalRbwvPackages) -and $HasSiblingRbwvSource)

    $PortableStage = Join-Path $RepoRoot 'artifacts/portable-stage'
    if (Test-Path -LiteralPath $PortableStage) { Remove-Item -LiteralPath $PortableStage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $PortableStage | Out-Null

    $PortableArgs = @(
        'publish'
        (Join-Path $RepoRoot 'src/RemotePCDiagnostics.Host/RemotePCDiagnostics.Host.csproj')
        '-c', 'Release'
        '-r', 'win-x64'
        '--self-contained', 'true'
        '-p:PublishProfile=Portable'
        '-p:GeneratePackageOnBuild=false'
        '-p:DebugType=None'
        '-p:DebugSymbols=false'
        "-p:Version=$Version"
    )
    if ($BuildFromRbwvSource) {
        $ResolvedRbwv = (Resolve-Path -LiteralPath $EffectiveRbwvRoot).Path
        $PortableArgs += '-p:UseRbwvSource=true'
        $PortableArgs += "-p:RbwvSourceRoot=$ResolvedRbwv"
    }
    $PortableArgs += @('-o', $PortableStage)

    Write-Host ""
    Write-Host "Publishing single-file Portable executable ($Version) ..." -ForegroundColor Cyan
    & dotnet @PortableArgs
    if ($LASTEXITCODE -ne 0) { throw "Portable dotnet publish failed ($LASTEXITCODE)" }

    $PortableSourceExe = Join-Path $PortableStage 'RemotePCDiagnostics.Host.exe'
    $PortableFileName  = "RemotePCDiagnostics-Portable-$Version-win-x64.exe"
    $PortableExePath   = Join-Path $OutputDir $PortableFileName
    $PortableShaPath   = "$PortableExePath.sha256"

    Copy-Item -LiteralPath $PortableSourceExe -Destination $PortableExePath -Force
    $PortableHash = (Get-FileHash -LiteralPath $PortableExePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText($PortableShaPath, "$PortableHash  $PortableFileName")

    $PortableMb = [Math]::Round((Get-Item -LiteralPath $PortableExePath).Length / 1MB, 2)
    Write-Host "Portable executable built: $PortableExePath ($PortableMb MB)" -ForegroundColor Green

    $ReleaseAssets += @($PortableExePath, $PortableShaPath)
}

if ($LocalOnly) {
    Write-Host ""
    Write-Host "LocalOnly specified - skipping GitHub pre-release upload. Built assets:" -ForegroundColor Green
    $ReleaseAssets | ForEach-Object { Write-Host "  $_" }
    return
}

# 6) Replace the single rolling GitHub pre-release ('prerelease'), removing any older pre-releases.
Push-Location $RepoRoot
try {
    $CommitSha = (& git rev-parse HEAD).Trim()
    $ShortSha  = $CommitSha.Substring(0, [Math]::Min(7, $CommitSha.Length))

    Write-Host ""
    Write-Host "Removing previous GitHub pre-releases so only one copy is kept ..." -ForegroundColor Cyan
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

    Write-Host "Publishing rolling GitHub pre-release 'prerelease' ($ShortSha) ..." -ForegroundColor Cyan
    & gh release create 'prerelease' @ReleaseAssets `
        --prerelease `
        --target $CommitSha `
        --title "Remote PC Diagnostics $Version ($ShortSha)" `
        --notes "Rolling pre-release built from commit $CommitSha."
    if ($LASTEXITCODE -ne 0) { throw "gh release create failed ($LASTEXITCODE)" }

    $ReleaseUrl = (& gh release view 'prerelease' --json url --jq '.url').Trim()
    Write-Host ""
    Write-Host "Published rolling pre-release:" -ForegroundColor Green
    Write-Host "  $ReleaseUrl"
}
finally {
    Pop-Location
}
