<#
.SYNOPSIS
  Authenticode-signs RPCD build outputs with the test PFX carried in GitHub Actions secrets.

.DESCRIPTION
  Used by the installer, Agent MSI, and MSIX build scripts. When WINDOWS_CODESIGN_PFX_BASE64 and
  WINDOWS_CODESIGN_PFX_PASSWORD are both unset, logs a notice and returns without signing so CI
  stays green. When both are set, signs with signtool (SHA-256, RFC 3161 timestamp) and checks
  each file with signtool verify /pa.

  The product installer does not call this script and does not install a certificate.

.PARAMETER File
  Files to sign as they are (setup EXE, Agent EXE, MSI, MSIX).

.PARAMETER AppDirectory
  Publish directories. Only RemotePCDiagnostics*.exe and RemotePCDiagnostics*.dll under them are
  signed. Third-party tools (osquery, HardeningKitty) and the .NET runtime are left alone.

.PARAMETER SubjectOnly
  Writes the certificate subject to the pipeline and does not sign. Empty output when the secrets
  are unset. The MSIX build uses this so Package/Identity/Publisher matches the certificate.
#>
[CmdletBinding()]
param(
    [string[]] $File,
    [string[]] $AppDirectory,
    [switch] $SubjectOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SecretPfx = 'WINDOWS_CODESIGN_PFX_BASE64'
$SecretPassword = 'WINDOWS_CODESIGN_PFX_PASSWORD'
$TimestampUrls = @(
    'http://timestamp.digicert.com'
    'http://timestamp.sectigo.com'
)

function Test-WindowsHost {
    return ($env:OS -eq 'Windows_NT') -or [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
}

function Get-RpcdSignTool {
    $roots = @()
    if (${env:ProgramFiles(x86)}) { $roots += Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin' }
    if ($env:ProgramFiles) { $roots += Join-Path $env:ProgramFiles 'Windows Kits\10\bin' }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $found = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '10.*' } |
            Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ } |
            Select-Object -First 1
        if ($found) { return $found }
    }
    $cmd = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    throw 'signtool.exe was not found. Install the Windows SDK (Windows Kits 10).'
}

function Test-CodeSigningCertificate {
    param($Certificate)
    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $sha256Rsa = '1.2.840.113549.1.1.11'
    $hasEku = $false
    foreach ($ext in $Certificate.Extensions) {
        $eku = $ext -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        if ($null -eq $eku) { continue }
        foreach ($use in $eku.EnhancedKeyUsages) {
            if ($use.Value -eq $codeSigningOid) { $hasEku = $true }
        }
    }
    if (-not $hasEku) {
        throw 'The PFX certificate is missing the Code Signing EKU (1.3.6.1.5.5.7.3.3). Create it with scripts/signing/New-RpcdTestSigningCert.ps1.'
    }
    if ($Certificate.SignatureAlgorithm.Value -ne $sha256Rsa) {
        throw "The PFX signature algorithm is $($Certificate.SignatureAlgorithm.FriendlyName). Use SHA-256 (sha256RSA)."
    }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if ($null -eq $rsa) {
        throw 'The PFX does not contain an RSA key. Create it with scripts/signing/New-RpcdTestSigningCert.ps1 (RSA 3072 or more).'
    }
    # RSA.KeySize is not readable from PowerShell on every runtime. The modulus length is the key size.
    $keyBits = $rsa.ExportParameters($false).Modulus.Length * 8
    if ($keyBits -lt 3072) {
        throw "The PFX RSA key is $keyBits bits. Use 3072 or more."
    }
}

function Export-PublicCertificate {
    param($Certificate)
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $dir = Join-Path $repoRoot 'artifacts/signing'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $path = Join-Path $dir 'rpcd-test-codesign.cer'
    [System.IO.File]::WriteAllBytes($path, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host "Wrote public test certificate $path (safe to publish; the private key stays in the PFX secret)."
    return $path
}

function Import-RunnerTrust {
    param(
        [string] $CerPath,
        [string] $Thumbprint
    )
    # signtool verify /pa checks the chain. A self-signed certificate is trusted on this
    # ephemeral runner only. The product installer never installs a certificate.
    $stores = @(
        'Cert:\LocalMachine\TrustedPublisher'
        'Cert:\LocalMachine\Root'
        'Cert:\LocalMachine\TrustedPeople'
    )
    foreach ($store in $stores) {
        $present = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $Thumbprint })
        if ($present.Count -gt 0) { continue }
        Import-Certificate -FilePath $CerPath -CertStoreLocation $store | Out-Null
    }
    Write-Host "Imported the test certificate into this runner's Trusted Publisher, Trusted Root, and Trusted People stores so 'signtool verify /pa' can succeed. The installer does not do this."
}

function Get-AppBinaries {
    param([string] $Directory)
    if (-not (Test-Path -LiteralPath $Directory)) {
        throw "App directory was not found: $Directory"
    }
    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    $found = @(Get-ChildItem -LiteralPath $resolved -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            ($_.Extension -eq '.exe' -or $_.Extension -eq '.dll') -and $_.Name -like 'RemotePCDiagnostics*'
        } | ForEach-Object { $_.FullName })
    if ($found.Count -eq 0) {
        throw "No RemotePCDiagnostics executables or DLLs to sign under $resolved."
    }
    return $found
}

$pfxValue = [Environment]::GetEnvironmentVariable($SecretPfx)
$password = [Environment]::GetEnvironmentVariable($SecretPassword)
if ($null -ne $pfxValue) { $pfxValue = $pfxValue.Trim() }
if ($null -ne $password) { $password = $password.Trim() }
$hasPfx = -not [string]::IsNullOrWhiteSpace($pfxValue)
$hasPassword = -not [string]::IsNullOrWhiteSpace($password)
if (-not $hasPfx -and -not $hasPassword) {
    if ($env:RPCD_CODESIGN_SKIP_LOGGED -ne '1') {
        Write-Host "::notice title=Code signing::Code signing skipped: GitHub Actions secrets $SecretPfx and $SecretPassword are not set. Packages stay unsigned."
        $env:RPCD_CODESIGN_SKIP_LOGGED = '1'
    }
    return
}
if (-not $hasPfx -or -not $hasPassword) {
    throw "Code signing is only partly configured. Set both secrets $SecretPfx and $SecretPassword, or leave both unset."
}

$paths = New-Object System.Collections.Generic.List[string]
if ($File) {
    foreach ($one in $File) {
        if ([string]::IsNullOrWhiteSpace($one)) { continue }
        if (-not (Test-Path -LiteralPath $one)) { throw "File to sign was not found: $one" }
        $paths.Add((Resolve-Path -LiteralPath $one).Path) | Out-Null
    }
}
if ($AppDirectory) {
    foreach ($dir in $AppDirectory) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        foreach ($binary in @(Get-AppBinaries -Directory $dir)) {
            if (-not $paths.Contains($binary)) { $paths.Add($binary) | Out-Null }
        }
    }
}
if (-not $SubjectOnly -and $paths.Count -eq 0) {
    throw 'Pass -File, -AppDirectory, or -SubjectOnly.'
}

$pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) ('rpcd-codesign-' + [guid]::NewGuid().ToString('n') + '.pfx')
$cert = $null
try {
    $compact = ($pfxValue -replace '\s', '')
    try {
        [System.IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($compact))
    }
    catch {
        throw "$SecretPfx is not valid base64 of a PFX file. Paste the single line from artifacts/signing/rpcd-test-codesign.pfx.b64."
    }

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    try {
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $password, $flags)
        }
        catch {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $password)
        }
    }
    catch {
        throw "Could not read the PFX. Check that $SecretPassword is the password from New-RpcdTestSigningCert.ps1 and that $SecretPfx is the single-line base64 of that PFX. $($_.Exception.GetBaseException().Message)"
    }
    Test-CodeSigningCertificate -Certificate $cert
    $publicCer = Export-PublicCertificate -Certificate $cert
    Write-Host "Test signing certificate subject: $($cert.Subject)"
    Write-Host "Test signing certificate thumbprint: $($cert.Thumbprint)"

    if ($SubjectOnly) {
        Write-Output $cert.Subject
        return
    }

    if (-not (Test-WindowsHost)) {
        throw 'signtool code signing requires Windows.'
    }

    $signTool = Get-RpcdSignTool
    if ($env:GITHUB_ACTIONS -eq 'true') {
        Import-RunnerTrust -CerPath $publicCer -Thumbprint $cert.Thumbprint
    }

    $pending = New-Object System.Collections.Generic.List[string]
    foreach ($path in $paths) {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.SignerCertificate -and $signature.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
            Write-Host "Already signed by this certificate: $path"
            continue
        }
        $pending.Add($path) | Out-Null
    }

    if ($pending.Count -gt 0) {
        $failures = New-Object System.Collections.Generic.List[string]
        $offset = 0
        while ($offset -lt $pending.Count) {
            $take = [Math]::Min(15, $pending.Count - $offset)
            $batch = @($pending.GetRange($offset, $take))
            $batchSigned = $false
            foreach ($url in $TimestampUrls) {
                Write-Host "signtool sign /fd SHA256 /tr $url /td SHA256 ($take file(s))"
                & $signTool sign /fd SHA256 /tr $url /td SHA256 /f $pfxPath /p $password @batch
                if ($LASTEXITCODE -eq 0) {
                    $batchSigned = $true
                    break
                }
                $failures.Add("timestamp $url failed ($LASTEXITCODE)") | Out-Null
            }
            if (-not $batchSigned) {
                throw "signtool sign failed for $($batch -join ', '). $($failures -join '; ')"
            }
            $offset += $take
        }
    }

    foreach ($path in $paths) {
        Write-Host "signtool verify /pa /v $path"
        & $signTool verify /pa /v $path
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verify /pa failed for $path ($LASTEXITCODE). Trust the public certificate with scripts/signing/Install-RpcdTestCert.ps1, then verify again."
        }
    }
    Write-Host "Signed and verified $($paths.Count) file(s)." -ForegroundColor Green
}
finally {
    if ($null -ne $cert) { $cert.Dispose() }
    if (Test-Path -LiteralPath $pfxPath) {
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
}
