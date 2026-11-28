<#
.SYNOPSIS
    Authenticode-signs a release file (Setup EXE or Agent MSI) with Microsoft Artifact Signing.

.DESCRIPTION
    Called by installer/Build-Installer.ps1 and msi/Build-AgentMsi.ps1 right before they write the .sha256 file, so the
    checksum always describes the signed file. Does nothing unless ARTIFACT_SIGNING_ENDPOINT, ARTIFACT_SIGNING_ACCOUNT
    and ARTIFACT_SIGNING_PROFILE are all set: local builds and CI without the signing secrets stay unsigned.

    Authentication is the Artifact Signing dlib's DefaultAzureCredential. In CI, azure/login (OIDC) signs the Azure CLI
    in first; on a workstation, run 'az login'. See docs/update-signing.md.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Endpoint = $env:ARTIFACT_SIGNING_ENDPOINT
$Account = $env:ARTIFACT_SIGNING_ACCOUNT
$CertProfile = $env:ARTIFACT_SIGNING_PROFILE
$configured = @(@($Endpoint, $Account, $CertProfile) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($configured.Count -eq 0) {
    Write-Host "Code signing skipped (Artifact Signing is not configured): $($Path -join ', ')" -ForegroundColor Yellow
    return
}
if ($configured.Count -ne 3) {
    throw 'Set all of ARTIFACT_SIGNING_ENDPOINT, ARTIFACT_SIGNING_ACCOUNT and ARTIFACT_SIGNING_PROFILE, or none of them.'
}

# Pinned Artifact Signing client (dlib). Update the version and SHA-512 together.
$DlibVersion = '1.0.146'
$DlibSha512 = 'fc6d211bf543212ea9b16db76f9b7557f3912209f43d500eb468fdc3e8643e602e238a5e9a97f0956e741361ad1ec727cfdfb9433de16c2e2671bede8f6627d4'
$TimestampUrl = 'http://timestamp.acs.microsoft.com'

function Get-SignTool {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $tool = Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'x64\signtool.exe') } |
        Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
        Select-Object -First 1
    if (-not $tool) { throw "signtool.exe (x64) was not found under $kits. Install the Windows SDK." }
    return (Join-Path $tool.FullName 'x64\signtool.exe')
}

function Get-Dlib {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "artifact-signing-$DlibVersion"
    $dlib = Join-Path $root 'bin\x64\Azure.CodeSigning.Dlib.dll'
    if (Test-Path -LiteralPath $dlib) { return $dlib }

    New-Item -ItemType Directory -Force $root | Out-Null
    $package = Join-Path $root 'client.nupkg'
    $url = "https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/$DlibVersion/microsoft.artifactsigning.client.$DlibVersion.nupkg"
    Invoke-WebRequest -Uri $url -OutFile $package -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $package -Algorithm SHA512).Hash
    if (-not [string]::Equals($actual, $DlibSha512, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $package -Force
        throw "Artifact Signing client package hash mismatch (got $actual)."
    }
    Expand-Archive -LiteralPath $package -DestinationPath $root -Force
    if (-not (Test-Path -LiteralPath $dlib)) { throw "Azure.CodeSigning.Dlib.dll missing from $package." }
    return $dlib
}

$signTool = Get-SignTool
$dlibPath = Get-Dlib
$metadata = Join-Path ([System.IO.Path]::GetTempPath()) ("artifact-signing-" + [guid]::NewGuid().ToString('N') + '.json')
@{
    Endpoint = $Endpoint
    CodeSigningAccountName = $Account
    CertificateProfileName = $CertProfile
    ExcludeCredentials = @('ManagedIdentityCredential', 'SharedTokenCacheCredential', 'VisualStudioCredential',
        'VisualStudioCodeCredential', 'InteractiveBrowserCredential')
} | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding UTF8

try {
    foreach ($file in $Path) {
        $full = (Resolve-Path -LiteralPath $file).Path
        Write-Host "Signing $full ..." -ForegroundColor Cyan
        & $signTool sign /v /fd SHA256 /tr $TimestampUrl /td SHA256 /dlib $dlibPath /dmdf $metadata $full
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed for $full ($LASTEXITCODE)." }
        & $signTool verify /pa /tw $full
        if ($LASTEXITCODE -ne 0) { throw "signtool verify failed for $full ($LASTEXITCODE)." }
    }
}
finally {
    Remove-Item -LiteralPath $metadata -Force -ErrorAction SilentlyContinue
}
