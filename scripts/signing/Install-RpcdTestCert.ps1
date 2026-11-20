<#
.SYNOPSIS
  Trusts or removes the RPCD test code-signing certificate on this PC.

.DESCRIPTION
  Run from an elevated PowerShell. Imports the public .cer into the LocalMachine
  Trusted Publisher, Trusted Root, and Trusted People stores, or removes that
  same thumbprint from those stores.

  This script is opt-in for the test laptops. The product installer does not run it
  and does not install a certificate or a trusted root.

.PARAMETER CerPath
  Public certificate (.cer). When omitted, the script looks next to itself
  (scripts/signing/rpcd-test-codesign.cer) and then in artifacts/signing/.

.PARAMETER Uninstall
  Remove this certificate's thumbprint from the three machine stores.
#>
[CmdletBinding()]
param(
    [string] $CerPath = '',
    [switch] $Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$windowsHost = ($env:OS -eq 'Windows_NT') -or [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
if (-not $windowsHost) {
    throw 'Install-RpcdTestCert.ps1 requires Windows.'
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session (Run as administrator). It changes the LocalMachine certificate stores.'
}

function Resolve-TestCerPath {
    param([string] $Requested)
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if (-not (Test-Path -LiteralPath $Requested)) { throw "Certificate not found: $Requested" }
        return (Resolve-Path -LiteralPath $Requested).Path
    }
    $candidates = @(
        (Join-Path $PSScriptRoot 'rpcd-test-codesign.cer')
        (Join-Path $PSScriptRoot '../../artifacts/signing/rpcd-test-codesign.cer')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    throw @"
Public certificate not found.
Pass -CerPath, or put the public file at scripts/signing/rpcd-test-codesign.cer.
CI attaches rpcd-test-codesign.cer to the GitHub release when the signing secrets are set.
Copy the .cer only. Do not copy the PFX onto a test laptop.
"@
}

$resolved = Resolve-TestCerPath -Requested $CerPath
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
try {
    $hasEku = $false
    foreach ($ext in $cert.Extensions) {
        $eku = $ext -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        if ($null -eq $eku) { continue }
        foreach ($use in $eku.EnhancedKeyUsages) {
            if ($use.Value -eq '1.3.6.1.5.5.7.3.3') { $hasEku = $true }
        }
    }
    if (-not $hasEku) {
        throw "Refusing to trust $resolved because it does not have the Code Signing EKU (1.3.6.1.5.5.7.3.3)."
    }

    $stores = @(
        'Cert:\LocalMachine\TrustedPublisher'
        'Cert:\LocalMachine\Root'
        'Cert:\LocalMachine\TrustedPeople'
    )
    Write-Host "Subject:    $($cert.Subject)"
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host "File:       $resolved"

    if ($Uninstall) {
        foreach ($store in $stores) {
            $matches = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
            if ($matches.Count -eq 0) {
                Write-Host "Not present: $store"
                continue
            }
            foreach ($match in $matches) { Remove-Item -LiteralPath $match.PSPath -Force }
            Write-Host "Removed:     $store"
        }
        Write-Host 'The test certificate was removed from this PC. Other trusted roots were left in place.' -ForegroundColor Green
        return
    }

    foreach ($store in $stores) {
        $matches = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
        if ($matches.Count -gt 0) {
            Write-Host "Already present: $store"
            continue
        }
        Import-Certificate -FilePath $resolved -CertStoreLocation $store | Out-Null
        Write-Host "Imported:        $store"
    }
}
finally {
    $cert.Dispose()
}

Write-Host ''
Write-Host 'This PC now trusts the test certificate.' -ForegroundColor Green
Write-Host 'Trusted Publisher: Authenticode reports the test publisher.'
Write-Host 'Trusted Root: the self-signed chain ends in a root on this PC. Treat the private key as a key to this PC.'
Write-Host 'Trusted People: App Installer accepts an MSIX signed by this certificate (https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide).'
Write-Host 'A file downloaded from GitHub still has Mark of the Web. Clear it or SmartScreen can still warn:'
Write-Host '  Unblock-File -LiteralPath .\RemotePCDiagnostics-Setup-*-win-x64.exe'
Write-Host 'Details and the removal command are in docs/code-signing.md.'
