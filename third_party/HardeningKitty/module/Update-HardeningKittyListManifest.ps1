<#
.SYNOPSIS
    Generate and sign the HardeningKitty finding-list manifest

     =^._.^=
    _(      )/  HardeningKitty


    Author:  Michael Schneider
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION
    Builds lists\hardeningkitty_lists_manifest.psd1 - a readable PowerShell data file mapping every official
    finding list (*.csv) to its SHA-256 hash - and produces a detached PKCS#7 signature
    lists\hardeningkitty_lists_manifest.psd1.p7s using the maintainer code-signing certificate.

    HardeningKitty verifies a finding list by checking this detached signature with
    SignedCms.CheckSignature($true) (signature integrity only, chain/validity ignored) and by
    matching the signer certificate thumbprint against the value pinned in HardeningKitty.psm1
    ($HardeningKittyListSigningThumbprint). A self-signed certificate is therefore sufficient and
    no timestamp is required.

    Re-run this script whenever the lists are regenerated (e.g. as a release / CI step).

.PARAMETER ListDirectory
    Directory containing the *.csv finding lists. Defaults to the lists\ folder next to this script.

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.PARAMETER PfxPath
    Path to a PFX file holding the signing certificate and its private key.

.PARAMETER PfxPassword
    Password for the PFX as a SecureString. If omitted with -PfxPath, you are prompted.

.EXAMPLE
    .\Update-HardeningKittyListManifest.ps1 -CertificateThumbprint $cert.Thumbprint

.EXAMPLE
    .\Update-HardeningKittyListManifest.ps1 -PfxPath .\signing-key.pfx
#>

[CmdletBinding(DefaultParameterSetName = "Store")]
param (
    [String]
    $ListDirectory = (Join-Path -Path $PSScriptRoot -ChildPath "lists"),

    [Parameter(Mandatory = $true, ParameterSetName = "Store")]
    [String]
    $CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = "Pfx")]
    [String]
    $PfxPath,

    [Parameter(ParameterSetName = "Pfx")]
    [System.Security.SecureString]
    $PfxPassword
)

$Version = "0.0.1"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# The PKCS#7/CMS types (SignedCms, ContentInfo, CmsSigner) live in the System.Security assembly,
# which is not loaded by default on Windows PowerShell 5.1. It is already present on PowerShell 7.
if (-not ([System.Management.Automation.PSTypeName]'System.Security.Cryptography.Pkcs.SignedCms').Type) {
    Add-Type -AssemblyName System.Security
}

$ManifestName  = "hardeningkitty_lists_manifest.psd1"
$ManifestPath  = Join-Path -Path $ListDirectory -ChildPath $ManifestName
$SignaturePath = "$ManifestPath.p7s"

#
# Header
#
Write-Output "`n"
Write-Output "      =^._.^="
Write-Output "     _(      )/  HardeningKitty List Manifest Tool $Version"
Write-Output "`n"

if (-not (Test-Path -LiteralPath $ListDirectory)) {
    throw "List directory not found: $ListDirectory"
}

#
# Load the signing certificate
#
if ($PSCmdlet.ParameterSetName -eq "Pfx") {
    if (-not (Test-Path -LiteralPath $PfxPath)) {
        throw "PFX file not found: $PfxPath"
    }
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host -AsSecureString "PFX password"
    }
    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $PfxPath,
        $PfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    )
} else {
    $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint", "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Certificate) {
        throw "No certificate with thumbprint $CertificateThumbprint found in Cert:\CurrentUser\My or Cert:\LocalMachine\My"
    }
}

if (-not $Certificate.HasPrivateKey) {
    throw "The signing certificate does not have an associated private key."
}

Write-Host "[*] Signing certificate: $($Certificate.Subject) ($($Certificate.Thumbprint))"

#
# Build the manifest
#
$Lists = Get-ChildItem -Path $ListDirectory -Filter "*.csv" -File | Sort-Object -Property Name

if ($Lists.Count -eq 0) {
    throw "No *.csv finding lists found in $ListDirectory"
}

$Builder = New-Object System.Text.StringBuilder
[void]$Builder.AppendLine("@{")
[void]$Builder.AppendLine("    Version   = 1")
[void]$Builder.AppendLine("    Algorithm = 'SHA256'")
[void]$Builder.AppendLine("    Lists     = @{")
foreach ($List in $Lists) {
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $List.FullName).Hash
    [void]$Builder.AppendLine("        '$($List.Name)' = '$Hash'")
}
[void]$Builder.AppendLine("    }")
[void]$Builder.AppendLine("}")

# Write deterministically as UTF-8 without BOM; the detached signature is over these exact bytes.
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, $Builder.ToString(), $Utf8NoBom)
Write-Host "[*] Wrote manifest: $ManifestPath ($($Lists.Count) lists)"

# Sanity check: the manifest must be parseable as a data file
$null = Import-PowerShellDataFile -Path $ManifestPath

#
# Produce a detached PKCS#7 signature over the manifest bytes
#
$ManifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
$ContentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $ManifestBytes)
$SignedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms($ContentInfo, $true)   # detached
$CmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner($Certificate)
# Embed the signer certificate so the verifier can read its thumbprint. EndCertOnly is required:
# the default (ExcludeRoot) would drop a self-signed certificate, which is its own root.
$CmsSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
$CmsSigner.DigestAlgorithm = New-Object System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1")  # SHA-256
$SignedCms.ComputeSignature($CmsSigner)
[System.IO.File]::WriteAllBytes($SignaturePath, $SignedCms.Encode())
Write-Host "[*] Wrote detached signature: $SignaturePath"

#
# Self-verify the way HardeningKitty will
#
$Verify = New-Object System.Security.Cryptography.Pkcs.SignedCms(
    (New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $ManifestBytes)),
    $true
)
$Verify.Decode([System.IO.File]::ReadAllBytes($SignaturePath))
$Verify.CheckSignature($true)
Write-Host "[+] Signature verifies. Signer thumbprint: $($Verify.SignerInfos[0].Certificate.Thumbprint)"
Write-Host "[+] Ensure `$HardeningKittyListSigningThumbprint in HardeningKitty.psm1 is set to this thumbprint."

# SIG # Begin signature block
# MIItNQYJKoZIhvcNAQcCoIItJjCCLSICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtEauEco2lc76BPwjSpy1hZai
# 7oyggiZsMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGHDCCBASgAwIBAgIQM9cIqJFAUxnipbvTObmtbjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBXMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgRVYgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEAu9H+HrdCW3j1kKeuLIPxjSHTMIaFe9/TzdkWS6yFxbsBz+KMKBFy
# BHYsgcWrEnpASsUQ6IEUORtfTwf2MDAwfzUl5cBzPUAJlOio+Os5C1XVtgyLHif4
# 3j4iwb/vZe5z7mXdKN27H32bMn+3mVUXqrJJqDwQajrDIbKZqEPXO4KoGWG1Pmpa
# Xbi8nhPQCp71W49pOGjqpR9byiPuC+280B5DQ26wU4zCcypEMW6+j7jGAva7ggQV
# eQxSIOiYJ3Fh7y/k+AL7M1m19MNV59/2CCKuttEJWewBn3OJt0NP1fLZvVZZCd23
# F/bEdIC6h0asBtvbBA3VTrrujAk0GZUb5nATBCXfj7jXhDOMbKYM62i6lU98ROjU
# aY0lecMh8TV3+E+2ElWV0FboGALV7nnIhqFp8RtOlBNqB2Lw0GuZpZdQnhwzoR7u
# YYsFaByO9e4mkIPW/nGFp5ryDRQ+NrUSrXd1esznRjZqkFPLxpRx3gc6IfnWMmfg
# nG5UhqBkoIPLAgMBAAGjggFjMIIBXzAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAdBgNVHQ4EFgQUgTKSQSsozUbIxKLGKjkS7EipPxQwDgYDVR0PAQH/
# BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# GgYDVR0gBBMwETAGBgRVHSAAMAcGBWeBDAEDMEsGA1UdHwREMEIwQKA+oDyGOmh0
# dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nUm9v
# dFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUFBzAChjpodHRwOi8vY3J0
# LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYucDdj
# MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEAXzas+/n2cloUt/ALHd7Y/ZcB0v0B7pkthuj2t/A5/9aBSlqnQkoK
# LRWd5pT9xWlKstdL8RYSTPa+kGZliy101KsI92oRAwh3fL5p4bDbnySJA9beXKTg
# sta0z+M41bltzCfWzmQR6BBydtP54OksielJ07OXlgYK4fYKyEGakV2B2DZ3mMqA
# QZeo+JE/Y5+qzVRUS4Dq9Rdm05Rx/Z79RzHj6RqGHdO+INI/sVJfspO9jJUJmHKP
# lQH0mEOlSvsUJqqdNr9ysPzcvYQN7O00qF6VKzgWYwV12fYxLhVr4pSyKtJ0NbWY
# mqP++CsvthdLJ2xa5rl2XtqG3atk1mrqgxiIGzGC9YizlCXAIS8IaQLjTLtMKhEw
# 64F5BuFBlSrUIPYLk+R8dgydHSZrX4QB9iqZza/ex/DkGKJOmy8qDGamknUmvtlA
# NRNvrqY3GnrorRxRYwcqVgZs7X4Y9uPsZHOmbQg2i68Pma51axcrwk1qw1FGQVbp
# j8KN/xNxm9rtntOfq+VFphLFFFpSQZejBgAIxeYc6ieCPDvb5kbE7y0ANRPNNn2d
# 5aonCAXMzsA2DksZT9Bjmm2/xSlTMSLbdVB3htDy+GruawYbPoUjK5fIfnqZQQzd
# WH8OqMMSPTo1m+CdLIwXgVREqHodmJ2Wf1lYplRl/1FCC/hH68/45b8wggaCMIIE
# aqADAgECAhA2wrC9fBs656Oz3TbLyXVoMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENp
# dHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNF
# UlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAw
# MDBaFw0zODAxMTgyMzU5NTlaMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCIndi5
# RWedHd3ouSaBmlRUwHxJBZvMWhUP2ZQQRLRBQIF3FJmp1OR2LMgIU14g0JIlL6VX
# WKmdbmKGRDILRxEtZdQnOh2qmcxGzjqemIk8et8sE6J+N+Gl1cnZocew8eCAawKL
# u4TRrCoqCAT8uRjDeypoGJrruH/drCio28aqIVEn45NZiZQI7YYBex48eL78lQ0B
# rHeSmqy1uXe9xN04aG0pKG9ki+PC6VEfzutu6Q3IcZZfm00r9YAEp/4aeiLhyaKx
# LuhKKaAdQjRaf/h6U13jQEV1JnUTCm511n5avv4N+jSVwd+Wb8UMOs4netapq5Q/
# yGyiQOgjsP/JRUj0MAT9YrcmXcLgsrAimfWY3MzKm1HCxcquinTqbs1Q0d2VMMQy
# i9cAgMYC9jKc+3mW62/yVl4jnDcw6ULJsBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h
# 90/QpZnBkhdtixMiWDVgh60KmLmzXiqJc6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCc
# jw5rmzajLbmqGygEgaj/OLoanEWP6Y52Hflef3XLvYnhEY4kSirMQhtberRvaI+5
# YsD3XVxHGBjlIli5u+NrLedIxsE88WzKXqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbE
# rg7ebeAQUQiS/uRGZ58NHs57ZPUfECcgJC+v2wIDAQABo4IBFjCCARIwHwYDVR0j
# BBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFPZ3at0//QET/xah
# bIICL9AKPRQlMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWg
# Q6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlm
# aWNhdGlvbkF1dGhvcml0eS5jcmwwNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzAB
# hhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAO
# vmVB7WhEuOWhxdQRh+S3OyWM637ayBeR7djxQ8SihTnLf2sABFoB0DFR6JfWS0sn
# f6WDG2gtCGflwVvcYXZJJlFfym1Doi+4PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3
# IBae91g50QyrVbrUoT0mUGQHbRcF57olpfHhQEStz5i6hJvVLFV/ueQ21SM99zG4
# W2tB1ExGL98idX8ChsTwbD/zIExAopoe3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZc
# bw4x4ztXLsGzqZIiRh5i111TW7HV1AtsQa6vXy633vCAbAOIaKcLAo/IU7sClyZU
# k62XD0VUnHD+YvVNvIGezjM6CRpcWed/ODiptK+evDKPU2K6synimYBaNH49v9Ih
# 24+eYXNtI38byt5kIvh+8aW88WThRpv8lUJKaPn37+YHYafob9Rg7LyTrSYpyZoB
# mwRWSE4W6iPjB7wJjJpH29308ZkpKKdpkiS9WNsf/eeUtvRrtIEiSJHN899L1P4l
# 6zKVsdrUu1FX1T/ubSrsxrYJD+3f3aKg6yxdbugot06YwGXXiy5UUGZvOu3lXlxA
# +fC13dQ5OlL2gIb5lmF6Ii8+CQOYDwXM+yd9dbmocQsHjcRPsccUd5E9FiswEqOR
# vz8g3s+jR3SFCgXhN4wz7NgAnOgpCdUo4uDyllU9PzCCBqcwggSPoAMCAQICEQCQ
# rAhyIP3Fp8RrXMcN9z0GMA0GCSqGSIb3DQEBDAUAMFcxCzAJBgNVBAYTAkdCMRgw
# FgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGlj
# IFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwHhcNMjYwMzI1MDAwMDAwWhcNNDEwMzI0
# MjM1OTU5WjBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFI0MTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK7kSqIBrYIcYvlmLVuaA8zw
# 1RfBhkn4G1CoemzjcYtML6yNUvKmwGH7y6/5MuSC1UYP/+9KYDSqvMQt/1hEKHYx
# MAD9oZpBkoaDQFEKbOJHelsKe+BaO0ZcENTKfePcraVkA7wrGAW2XHA5gQCQv4IK
# ori/3PNOXxnDMOk8yIMgVrlMeTxqfWJ4XkjT1xc2s9DD7URHWWJOFobTPoWs6mrD
# FlaY9FlAHDYTfbzvxQHVsvRmn3W+5ZmCwyk02I8KgGPT/UX4sTz41GiR+ppwUjQX
# a1+2tEHZbsdAKUtH3OPEVtZvlt7atx4h83IdRR8oYi8wjY3OjFKXFecWpQbzzsPx
# bUKPwMWiTrzwkrFa8dH/1pDKRJt371W62PfqKPayCr/XbnBOlRn8CALSmHnRtGzu
# AWtTJpcT3BKw6oy8IIL6wSbu938F6ZIbRNIc1dKbIJtr4ULN6R5ZfTdNEhwXctqp
# 3RHDbg4fuOl6LjNoaFwjud92EEDhzxFJzE1jqN4csceZIwxOT1aqfsfh0uFQE/lg
# TBuBs3i6/WL2W1OceWLy3XEdXRK1f0EWCuea6dNfX2RRdjUfk5EltFnJkN2+bWhn
# K14OPRKcyjOv5hKZ0iV4NRNd1+hjtva1rPyzb5Bs7EvFxqEQhgZbOq7qH3nm0rBw
# A0dxniBOYCFPdu246JCxAgMBAAGjggFuMIIBajAfBgNVHSMEGDAWgBT2d2rdP/0B
# E/8WoWyCAi/QCj0UJTAdBgNVHQ4EFgQUOnSlDGfGQlDC/bX8x7spNIL0erkwDgYD
# VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwIwYDVR0gBBwwGjAIBgZngQwBBAIwDgYMKwYBBAGyMQECAQMIMEwGA1Ud
# HwRFMEMwQaA/oD2GO2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1Ymxp
# Y1RpbWVTdGFtcGluZ1Jvb3RSNDYuY3JsMHwGCCsGAQUFBwEBBHAwbjBHBggrBgEF
# BQcwAoY7aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0
# YW1waW5nUm9vdFI0Ni5wN2MwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3Rp
# Z28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAy3lJHZvGeA2b43yhzoarvobHVzbfl
# +RfuPDwej0wCQkYAN6scTt2GwFe22qbOCv/tllqFlLKQZE+E9jVyuPTbyQHwrM7R
# 0oLapAEDC1+CowsqSRf/ptira5Pfd4PoHICnb9coPQtyZmHSQp5y9IGvqWf1qNfq
# 7V2fHZ8DvEQrLUzeoGF9BJRYu2OzacW3QQtUum3NOVf0gPRwv6I4991uhncJ6VP4
# lcpUpHZKB7R3hiIUC09mR9KjzPVnXHvL9n2bAwiUECfK5Zezhiw27F2tgi39DETf
# U8M4n0N6xLgFzsf05M5GURX8C9+IX9V6kpmmKtrUzMti4LD66gtmf+mSm934K81N
# L6YQeMEk1rpYrWPypcW76Mir6wb1AgseLIHqn/GkeuQm7zOTDf3f5WoX14qVNjZW
# NHF3JxkutV6ZnhinfCLfdv5bnwKWUfceqOajCVntI6uCbHxjBg6SCsexc5AfIGno
# 7gVFvwifT4XONPsSUaJ71XsJ+EvciVUVnjOO4qxm0fWJTd8a7jP8mc4ZPqwJvQFt
# Op7+6G+kUJAF0fnE8YgD8uttBReNTa1YmAeFMiqc38e8fI4eLm0zjM/eeGCHasno
# qqrbGwcF41iz9HXzFDwN4iD5z3QShp6HRiU3UpTwDJiiXcr0z6pjl7PyzJ3/tmWt
# GehV7CAfc/WlyzCCBr4wggUmoAMCAQICEFjX+P4AIZWTs1+TYQBns3swDQYJKoZI
# hvcNAQELBQAwVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIEVWIFIz
# NjAeFw0yMzA4MjEwMDAwMDBaFw0yNjA4MjAyMzU5NTlaMIGRMRgwFgYDVQQFEw9D
# SEUtMTA5LjgwNC4zODIxEzARBgsrBgEEAYI3PAIBAxMCQ0gxHTAbBgNVBA8TFFBy
# aXZhdGUgT3JnYW5pemF0aW9uMQswCQYDVQQGEwJDSDEQMA4GA1UECAwHWsO8cmlj
# aDEQMA4GA1UECgwHc2NpcCBhZzEQMA4GA1UEAwwHc2NpcCBhZzCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALNDqgJV5RRiMAJ5e8iGcC8Q2ENMyhFDeXm4
# KGGe3vqZVynLeacyvB7Gqosn3G+hfHg33kFeKWgFulrw4Zz9zU7ilqxUU/npeKp/
# QhppTAeppNagzYt2kRSjdaNQsZw3HFGhALdSLhRO0c5WWLEdTm4+jFWnkRoxveJb
# zJsUaNyhhF3VO+h762XjzXwqcBaueqfKgVVzk/Wh+H3efxkhv2Qvv1za7P3g+Jgx
# UJm8ZCLq9VPK1lIsi1inGw/jUHyrapf1pyZUqEHhVPB4/on8bZjwEbwNsska40S4
# JMpEuPijuEMSlgjs0qy0nJh/cAgBBP3MHgE0uWPfurpipf3+5nh1h3J0EmXeGLHm
# 7cjuEJusTcVtmR+Lm3wFgre//X5a30Lr66ihSZwtF2izyZhIHgi6wpEjiee6kJgL
# /ZuUBQJBLKnmMuw4l7F2BqVV0p7sCPyZ3raUFEZxrZqMILMYSmTmIAx+rjcScpxq
# iJjhqOxGeIN8oNGCQnUlRZUKILCIj9RO4tq/aKVCRzcHM+u/ctdBAzrx0B5HoSvQ
# /PjqJIn9veyAhtCie988KLfGtK9rF9W547whmBn6hjkzh9gTel5gjVQUNK6+OGak
# WWf86VWrpKBop7bCKA66e59Hd4M674u2rwe3pfhG/ktKtT8GMQ1GE+ynbt/JYAOI
# mlnuu7cBAgMBAAGjggHJMIIBxTAfBgNVHSMEGDAWgBSBMpJBKyjNRsjEosYqORLs
# SKk/FDAdBgNVHQ4EFgQU+U/LlyHiKHvC6PbxZXmvqntTohMwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSQYDVR0gBEIw
# QDA1BgwrBgEEAbIxAQIBBgEwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdv
# LmNvbS9DUFMwBwYFZ4EMAQMwSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQUVWUjM2LmNybDB7
# BggrBgEFBQcBAQRvMG0wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jcnQuc2VjdGlnby5j
# b20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FFVlIzNi5jcnQwIwYIKwYBBQUH
# MAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMDsGA1UdEQQ0MDKgIgYIKwYBBQUH
# CAOgFjAUDBJDSC1DSEUtMTA5LjgwNC4zODKBDG1pc2NAc2NpcC5jaDANBgkqhkiG
# 9w0BAQsFAAOCAYEAg/MzS935kdWYiX5Wx4LUNVSSS6RwRbtQb5uik5pPD+eqvp0z
# OqCWkIxOcO5grfNKXem1OVYKeiTUQaMU2yw9+vy6gWyCihuU5mkSCiVtzjmk29PQ
# RFI//zkw69MmpUfWR8mFYMAob0HEmSGSGVz1sT3wyC+uUQn+r/DH6Vcfvf1l56vC
# +zZj8wxR5Kpk+ZO5zZiSGItOmakhP0pdy+NhoVAHaYodF6tBOmYsaC7a3OjvKgkm
# sFwana2tAf7rx1ZOLLCwwTuCWutIqQlMH7ztSaJJN0RPHYfakY6Hrkd7f81B7/69
# wjZIEHQJdK3DYCGFF56aP/Dog2LYViSE7VJqD2KcX/UrrbD/+BmxJH9gHx2UbT4w
# Cw1o8loJedyI8/l8bZchmxBxop3x1P1j7C0ESKCg1fQmzQ2YxbC/KAvfekbCPMhz
# 213eTsqQ7eAl471UjmiqntE8gB7DQdMHk/JZLULQFc1Uwug412KekEZNenQ/wMfZ
# hiwcFCo+CYiBR5U3MIIG4jCCBMqgAwIBAgIRAOdO8lWwUE/626bf9/yLoxUwDQYJ
# KoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDEwHhcNMjYwMzI1MDAwMDAwWhcNMzcwNjI0MjM1OTU5WjByMQswCQYDVQQGEwJH
# QjEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWdu
# ZXIgUjM3MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsv/DbUvcUNlF
# LQURd9m4+1St5+JudFKo5P803Iks4mFeNB9SymodP6BJJWBuNhOFQj9w77AVAeg5
# qQpA2dIwp2QTyBHr2h9eWSTkMBVj9mV6+WI5SaW+vDZW7PhJTbysd9v9WB3Xt6ql
# Ei8m47pcTy8+k/OfhziKiuzNQXqfC7KcoRD/6up8OZBsU0qxr7n5nh/iRfAp1QXF
# TBQONBZSGIdHAyVRYYX033VoC8v71rizEKCpH97Pxbwcn9eq9K7W8h5v4npsMUoq
# CS/c8mQwylDQGx15dHYV6NlcVFdjXD11l7qCrIy/unH5OlZtgx58QJRXRbGgQyBd
# STpEpwuj3i5Qc52Z9m7hd7yCGCXKujf83hUQpOPx1w8+84EbEUTHVAfq4cpORaGW
# gY8NJy6txmd3wpS1MeXrOaVAMczTgzAZ+yZBWIqdgQBgTxEeXldEToZOrRkxvn1I
# jIlfr4I4NWJz+Rb52FshLVnkA/wdoad789Eb7XZDNKd4oMmnc636TgauaaVZP2LL
# oU0JD/fYr53hwBn4uXu5ZsSfpnqAT60S7szJm/Na882xEoyRzLJ+UVbXOlHLO63D
# KkAtdz1CDuwWxgRE1drnwplepT06dz+1yTr5p1AkUz21bzE6cT/8/kjh4OPzggYY
# qrOBQPfuKEL5ZJPcN9jRgEpYvRlq5ucCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaA
# FDp0pQxnxkJQwv21/Me7KTSC9Hq5MB0GA1UdDgQWBBRhEOl6Eq9RxIXU8s+kdA9Q
# zSCv+DAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDBKBgNVHSAEQzBBMAgGBmeBDAEEAjA1BgwrBgEEAbIxAQIBAwgw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwSgYDVR0fBEMw
# QTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGlt
# ZVN0YW1waW5nQ0FSNDEuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5
# aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5n
# Q0FSNDEuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEAA+o9jdGszfoZepOmygef1OlbkjrPd2QW9z3M8vVb
# QSCruPeO2eRsC9GhZ4CMZfhkrixayYD67gQkbyiRCbJu5L/i0NQjlQhBvbWfiEba
# +KHFKGud5YHRWhDZUtDeMIJGZG0BD7/sftZUo2Ifk+CXi/ZlM50+xK3OkqeXVi5G
# ubDD/5txmYuqCT3T3LAilmoB+5th9sQxiMhyQuT3R/aYb4vypoZJLYklUzTalXle
# W1nV9s4UROlE389CHDKAi/fepRSMnV8TghODDQxwzNGrOJZ04k/yhzHHDupfHPU5
# 1FYJqXIvWq9SAAWdlNV1JGIxhkp/TAtxBwz/Vd/VbgVb2d9/wRFfxFkka39O0+4x
# aZSl/oEK/1DqjxjJRO2Se9lGlJDScu21Zd23Cys3aYyB8y5H/+DFWtVe8PMKgr+V
# uIDp0Rk5bneVDAEW0TPAT8Ufwl2F6DJiDg/KZk5NmsYES+CxvF7bnISEnQh0ZrWn
# AJixquV0mElUx01wA5TuPIgyodxzNq/fC0hen9LBtdnfFfSZ+wt8A1Injsbio+DH
# Vq1voYiVNpBfO7+nh9NB4AhRXNldPgr3zgjJ+47s0uNYy2iDXAZSlkP3ym/7gy31
# jlu989SNpRWO14/LUNV2LSuXkRI1iLTPI6ZdXG0DnPPG7UftF0tk5m6BP9eNfr2t
# j1sxggYzMIIGLwIBATBrMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBFViBSMzYCEFjX+P4AIZWTs1+TYQBns3swCQYFKw4DAhoFAKB4MBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNI+0uo5
# HP0OB7DwlYx5NSfSxkRRMA0GCSqGSIb3DQEBAQUABIICAD7qNHlFnteL7xNXof+3
# KvzWxMaC3mE1d/BQjY9l7n9+qz8l3Bzr95paI2k+kvxVYT6xxxVZqzyjcGEdc41y
# NB6d7zVe8Puwqgri/V9V9nTSi75lCw3D4eTMnwEADOO0F0jmD4UWS2rgbgxU00On
# wGgzk5/hNB/Wyt49SHGhZYswvojOc7p+Ouqa4K4Vjff5EJozQCP8OzX3p0H5Ql1Q
# hPz1qstXfIr9GA1gtgBT+LKDMKdrEXI3xp1ww14OpqmW7YrB7rgpNjqSnzwQdc4u
# 9Fj7buADmi9eyVTyK0NELDeYl1w7OwB975xtOVQ4XMS44wnU3bIMhU/ZgJNrjSuy
# 6HlPvhC63UN+bMq9VXrmjRqHCEGzZevJ/cyTbn3dFQb/4ScQXhGQlNhswuj2YZHA
# a+fbSQ/CYU1i8FKQBV4ysFdA5Z6CiWjlAkNV+aPlIg6Uyxo2CG+JTqQJ9YpH3Xte
# Wx4dLpwvRsWBgnqmvupz5BSPfEqnh8DMaF1p/Edxvy2x18lXXn7Scvr9D2Kp7KJw
# qm4FaVyp1nnYtSGD8r95gcIuy8YVYTJHaLmkm1ZHUJszfUmqnJLAJ89T5CV7iR+q
# 8ojX2zs9mH0QOGZhonxhrg5f9YQE1k8NHzUCD4mGW1ABPRRiZlkv7ydehWrq0Aob
# ZX3/dLLektmUShNlE29tXn2XoYIDIzCCAx8GCSqGSIb3DQEJBjGCAxAwggMMAgEB
# MGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoG
# A1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSNDECEQDnTvJV
# sFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqG
# SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzIxMDUwMjM2WjA/BgkqhkiG9w0B
# CQQxMgQwqL/36s/DwMjeqSJvvhdJ/SXGbLzliET+GHttqxAJxm5AQZTaBpm7TVg4
# fLGDaWbjMA0GCSqGSIb3DQEBAQUABIICABtBMj0j4aREioIyRfRS7Vv99SS1xBEV
# x2RbsTRvnuQCoL2nszHzheimHMMnffY3M3QvoOPXMrRYWiWCQIb9kGaNHaXJiJQN
# vPIN4MdeEJnrW0K+azKWf56GTlXUu/RWYMQG9S6Fnsm2izvXu2iHQEWWMIyn5TWO
# hUUsIcLBPCvfr6/aRU4meNwzxE8fAGU3WWbrBKInXOXTUxmOGElEGFTwyWRqb/An
# eaeFvem0wnyEALpcTkcrZ+Oav+1Hpl3yoil9HrMYTZpc/19GokRGcTJvbQLCnD2j
# evDl9tqu1n04M6uWSX7yG89KsuRQ0H5DbdZceGMrxzhJzNwwOU7RxEe4eDl4Ih1j
# x1FnUIvfGECYszQSP3tB83F2JNH8Nl35ipkry/E5bRN2Ag6KOGGWd7uxDkO5JBrQ
# lPuYYK3jwyQBO+ACcDevZHW0JH0QXzGyVVfHAvg5hModQ2qpSDVHEterg/zQ1Z/y
# SnfCEVMdc9xRv1Cm+sf7YGIft6tN2/Xb7aVao88CtdU2jUTk4thYQCL/3btX3URO
# PanQ/gND0n19nRTGgBDMB3ZtmhCF85Hf9DOEBLp/vIbaVJB49kC2oe4RJmh7O6YL
# r+Y5U69OntnlWMaRWd0Wh9Ud8AC0+GQ2FG/ij0PHWBbuyx4cNuD6s3+WU9MA5j7K
# sODw8lLLeZU0
# SIG # End signature block
