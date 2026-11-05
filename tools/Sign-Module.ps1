<#
.SYNOPSIS
  Signs a module DLL: writes <Module>.dll.sig (base64 ECDSA P-256 / SHA-256, IEEE P1363) over the DLL's exact bytes.
.EXAMPLE
  ./tools/Sign-Module.ps1 -Module samples/SampleModule/bin/Release/net10.0/SampleModule.dll -PrivateKeyPath module-signing-key.pem
  The key can also come from the MODULE_SIGNING_KEY environment variable (the PEM text), for CI.
#>
param(
    [Parameter(Mandatory)][string]$Module,
    [string]$PrivateKeyPath
)
$ErrorActionPreference = 'Stop'
$pem = if ($PrivateKeyPath) { Get-Content -Path $PrivateKeyPath -Raw } else { $env:MODULE_SIGNING_KEY }
if (-not $pem) { throw 'Give -PrivateKeyPath or set MODULE_SIGNING_KEY.' }

$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Module))
$key = [System.Security.Cryptography.ECDsa]::Create()
try {
    $key.ImportFromPem($pem)
    if ($key.KeySize -ne 256) { throw 'The module signing key must be ECDSA P-256.' }
    $sig = $key.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
} finally { $key.Dispose() }
$sigPath = (Resolve-Path $Module).Path + '.sig'
Set-Content -Path $sigPath -Value ([Convert]::ToBase64String($sig)) -NoNewline -Encoding ascii
Write-Host "Signed: $sigPath"
