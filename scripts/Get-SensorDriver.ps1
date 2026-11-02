param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../artifacts/PawnIO-driver'))
$ErrorActionPreference = 'Stop'
$version = '2.2.0'
$expectedHash = '1F519A22E47187F70A1379A48CA604981C4FCF694F4E65B734AAA74A9FBA3032'
$url = "https://github.com/namazso/PawnIO.Setup/releases/download/$version/PawnIO_setup.exe"
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$installer = Join-Path $OutputDirectory 'PawnIO_setup.exe'
Invoke-WebRequest -Uri $url -OutFile $installer
if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'PawnIO installer hash mismatch; do not distribute this download.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=namazso\.eu(?:,|$)') {
    throw "PawnIO installer signature check failed: $($signature.Status)"
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../docs/sensor-driver-setup.md') -Destination (Join-Path $OutputDirectory 'README.md')
"$expectedHash  PawnIO_setup.exe" | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt')
Write-Output "Verified official PawnIO $version installer: $installer"
# Download and verification only. Never install a kernel driver as part of packaging/CI.
