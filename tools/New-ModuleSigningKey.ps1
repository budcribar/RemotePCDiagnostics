<#
.SYNOPSIS
  Creates the project's module signing key (ECDSA P-256) and writes its public half into ModuleLoader.cs.
.DESCRIPTION
  Run once, on a trusted PC. Keep the private key (module-signing-key.pem) offline or in a secret store: whoever holds it can make code
  run inside the elevated app. Modules that need administrator are signed only with this key. Partner modules stay unsigned and run in
  user mode.
#>
param(
    [string]$PrivateKeyPath = (Join-Path $PWD 'module-signing-key.pem'),
    [string]$LoaderPath = (Join-Path $PSScriptRoot '..\src\RemotePCDiagnostics.Core\Plugins\ModuleLoader.cs'),
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
if ((Test-Path $PrivateKeyPath) -and -not $Force) { throw "$PrivateKeyPath exists. Use -Force to replace it (modules signed with the old key stop loading)." }

$key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    Set-Content -Path $PrivateKeyPath -Value $key.ExportPkcs8PrivateKeyPem() -NoNewline -Encoding ascii
    $public = $key.ExportSubjectPublicKeyInfoPem()
} finally { $key.Dispose() }

$escaped = ($public -replace "`r", '') -replace "`n", '\n'
$source = Get-Content -Path $LoaderPath -Raw
$updated = [regex]::Replace($source, 'public const string PublicKeyPem = ".*?";', "public const string PublicKeyPem = `"$escaped`";")
if ($updated -eq $source) { throw "PublicKeyPem not found in $LoaderPath" }
[System.IO.File]::WriteAllText((Resolve-Path $LoaderPath), $updated, [System.Text.UTF8Encoding]::new($false))
Write-Host "Private key: $PrivateKeyPath (keep it secret)"
Write-Host "Public key written to $LoaderPath"
