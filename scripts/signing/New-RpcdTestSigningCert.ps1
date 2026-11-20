<#
.SYNOPSIS
  Creates the self-signed test code-signing certificate for the five test laptops.

.DESCRIPTION
  Writes a password-protected PFX, a one-line base64 copy of that PFX for the
  WINDOWS_CODESIGN_PFX_BASE64 GitHub secret, and a public .cer. Nothing here is committed
  unless you later copy only the .cer into this folder yourself.

  Run this on your own Windows PC. Do not run it in GitHub Actions.

.PARAMETER Subject
  Certificate subject. The MSIX Package/Identity/Publisher must be this exact string.
  Default: CN=Remote PC Diagnostics Test Code Signing

.PARAMETER Years
  Validity in years. 3 to 5. Default: 5.

.PARAMETER KeyLength
  RSA key size. 3072 or 4096. Default: 3072.

.PARAMETER OutputDir
  Where the PFX, base64 file, and public certificate are written.
  Default: artifacts/signing (gitignored).

.PARAMETER Password
  PFX password. Omit it to be prompted, so the password is not stored in shell history.

.PARAMETER Force
  Replace an existing PFX in the output directory.
#>
[CmdletBinding()]
param(
    [string] $Subject = 'CN=Remote PC Diagnostics Test Code Signing',
    [ValidateRange(3, 5)]
    [int] $Years = 5,
    [ValidateSet(3072, 4096)]
    [int] $KeyLength = 3072,
    [string] $OutputDir = '',
    [string] $Password = '',
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -eq 'true') {
    throw 'Do not create the test signing key on a GitHub Actions runner. Run this script on your own PC and upload the PFX as a secret.'
}

$windowsHost = ($env:OS -eq 'Windows_NT') -or [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
if (-not $windowsHost) {
    throw 'New-RpcdTestSigningCert.ps1 requires Windows (New-SelfSignedCertificate).'
}

if ($Subject -notmatch '^CN=.+') {
    throw "Subject must be a certificate subject starting with CN=. Got: $Subject"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'artifacts/signing'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$pfxPath = Join-Path $OutputDir 'rpcd-test-codesign.pfx'
$b64Path = Join-Path $OutputDir 'rpcd-test-codesign.pfx.b64'
$cerPath = Join-Path $OutputDir 'rpcd-test-codesign.cer'
if ((Test-Path -LiteralPath $pfxPath) -and -not $Force) {
    throw "$pfxPath already exists. Pass -Force to replace it. Packages signed with the old certificate will not match the new one."
}

if ([string]::IsNullOrEmpty($Password)) {
    $first = Read-Host -AsSecureString 'PFX password (at least 12 characters; not written to disk except inside the PFX)'
    $second = Read-Host -AsSecureString 'Confirm PFX password'
    $firstPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
    $secondPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
    try {
        $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($firstPtr)
        $confirm = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secondPtr)
        if ($Password -cne $confirm) { throw 'Passwords did not match.' }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPtr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPtr)
    }
}
if ($Password.Length -lt 12) {
    throw 'Use a PFX password of at least 12 characters.'
}

$notAfter = (Get-Date).AddYears($Years)
$notBefore = (Get-Date).AddMinutes(-10)
Write-Host "Creating $Subject (RSA $KeyLength, SHA-256, valid until $($notAfter.ToString('yyyy-MM-dd')))." -ForegroundColor Cyan

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyAlgorithm RSA `
    -KeyLength $KeyLength `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -FriendlyName 'Remote PC Diagnostics Test Code Signing'

try {
    $ekuOk = $false
    foreach ($ext in $cert.Extensions) {
        $eku = $ext -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        if ($null -eq $eku) { continue }
        foreach ($use in $eku.EnhancedKeyUsages) {
            if ($use.Value -eq '1.3.6.1.5.5.7.3.3') { $ekuOk = $true }
        }
    }
    if (-not $ekuOk) { throw 'New-SelfSignedCertificate did not set the Code Signing EKU (1.3.6.1.5.5.7.3.3).' }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $keyBits = 0
    if ($null -ne $rsa) { $keyBits = $rsa.ExportParameters($false).Modulus.Length * 8 }
    if ($keyBits -lt 3072) { throw 'The new certificate does not have an RSA key of 3072 bits or more.' }
    if ($cert.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11') {
        throw "Expected sha256RSA, got $($cert.SignatureAlgorithm.FriendlyName)."
    }
    $thumbprint = $cert.Thumbprint
    $createdSubject = $cert.Subject

    $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secure | Out-Null
    [System.IO.File]::WriteAllBytes($cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($pfxPath))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($b64Path, $b64, $utf8)

    # Reload the PFX to prove the password and the subject round-trip.
    $loaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $Password)
    try {
        if ($loaded.Thumbprint -ne $cert.Thumbprint) { throw 'Exported PFX thumbprint does not match the new certificate.' }
        if ($loaded.Subject -ne $createdSubject) { throw 'Exported PFX subject does not match the new certificate.' }
    }
    finally { $loaded.Dispose() }
}
finally {
    $cert.Dispose()
}

Write-Host ''
Write-Host 'Certificate created.' -ForegroundColor Green
Write-Host "  Subject:     $createdSubject"
Write-Host "  Thumbprint:  $thumbprint"
Write-Host "  Public cert: $cerPath"
Write-Host "  PFX:         $pfxPath"
Write-Host "  Base64 PFX:  $b64Path"
Write-Host ''
Write-Host 'GitHub repository secrets (Settings, Secrets and variables, Actions, New repository secret):'
Write-Host ''
Write-Host '  WINDOWS_CODESIGN_PFX_BASE64'
Write-Host '    The single line in the base64 file. Copy it with:'
Write-Host "    Get-Content -Raw '$b64Path' | Set-Clipboard"
Write-Host '    Do not print that line into a commit, a log, or a pull request.'
Write-Host ''
Write-Host '  WINDOWS_CODESIGN_PFX_PASSWORD'
Write-Host '    The password you just chose. It is not saved outside the PFX.'
Write-Host ''
Write-Host 'Do not commit the PFX or the base64 file. Both are gitignored (*.pfx, *.pfx.b64), and artifacts/ is gitignored.'
Write-Host 'You may commit only the public .cer, copied to scripts/signing/rpcd-test-codesign.cer.'
Write-Host 'CI also attaches that public certificate to the GitHub release once the secrets are set.'
Write-Host ''
Write-Host 'The private key is also in Cert:\CurrentUser\My on this PC. That is useful if this PC is one of the test laptops.'
Write-Host 'Remove it from the user store later if the PFX should be the only copy of the key.'
Write-Host 'Trust the public certificate on each test laptop with scripts/signing/Install-RpcdTestCert.ps1.'
Write-Host 'See docs/code-signing.md. The MSIX publisher must be this exact subject:'
Write-Host "  $createdSubject"
