# Release signing and the update publisher check

Standalone updates (the in-app Update button, the elevated helper, and Admin's `update_rpcd`) download Setup and the
Agent MSI from this repository's GitHub releases. Each file must match its release's `.sha256` file. Once a publisher
is pinned, each file must also carry a valid Authenticode signature from that publisher, checked right after the
download and again right before Setup starts. Microsoft Store updates use the Store's own path.

The pieces:

- `installer/Sign-ReleaseFile.ps1` signs a file with Microsoft Artifact Signing (signtool plus the pinned
  `Microsoft.ArtifactSigning.Client` dlib). `installer/Build-Installer.ps1` and `msi/Build-AgentMsi.ps1` call it right
  before they write the `.sha256` file, so checksums always describe the signed file. Without the
  `ARTIFACT_SIGNING_*` variables it prints "Code signing skipped" and does nothing.
- `.github/workflows/ci.yml` signs only on `main` and `v*` tags (`SIGN_RELEASE`), after an OIDC sign-in to Azure.
  Pull requests and other branches build unsigned.
- `UpdatePublisher.Pin` (`src/RemotePCDiagnostics.Core/Session/UpdatePublisher.cs`) is the pinned publisher: the
  certificate's CN, the Artifact Signing identity EKU, and the SHA-256 of the root certificate. While it is null the
  check is off. Once it is set, unsigned packages and packages from anyone else are refused.

## One-time setup

1. **Artifact Signing account.** In the Azure portal, create an Artifact Signing (formerly Trusted Signing) account
   (Basic SKU) in a region from the dlib README, for example East US (`https://eus.codesigning.azure.net`).
2. **Identity validation.** In the account, create a Public identity validation (Individual or Organization). This
   takes a few business days. The validated name becomes the certificate's CN.
3. **Certificate profile.** Create a Public Trust certificate profile linked to that identity validation.
4. **App registration for GitHub.** In Microsoft Entra ID, create an app registration. Under Certificates & secrets,
   add two federated credentials (GitHub Actions scenario, repository `budcribar/RemotePCDiagnostics`):
   entity type Branch `main`, and entity type Tag `v*`. No client secret is needed.
5. **Role.** On the Artifact Signing account, assign the app registration the *Artifact Signing Certificate Profile
   Signer* role (older name: *Trusted Signing Certificate Profile Signer*).
6. **Repository variables** (Settings > Secrets and variables > Actions > Variables; none of these are secrets):
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `ARTIFACT_SIGNING_ENDPOINT`, `ARTIFACT_SIGNING_ACCOUNT`,
   `ARTIFACT_SIGNING_PROFILE`.

The next push to `main` signs Setup and the Agent MSI. The job logs show `signtool verify` output for each file.

## Turning the check on

Only after a signed build is published, and a PC on that build has updated once:

1. Download a signed Setup from the prerelease and read the three values on Windows:

   ```powershell
   $sig  = Get-AuthenticodeSignature .\RemotePCDiagnostics-Setup-<version>-win-x64.exe
   $leaf = $sig.SignerCertificate
   $leaf.GetNameInfo('SimpleName', $false)                                    # SubjectCommonName
   $leaf.EnhancedKeyUsageList | Where-Object ObjectId -like '1.3.6.1.4.1.311.97.*'  # IdentityEkuOid (the longest one)
   $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
   $null = $chain.Build($leaf)
   $chain.ChainElements[-1].Certificate.GetCertHashString('SHA256')           # RootCertificateSha256
   ```

2. Set `UpdatePublisher.Pin` to `new UpdatePublisherPin("<CN>", "<EKU>", "<root SHA-256>")` and update
   `UpdatePublisherTests.Check_is_off_until_a_publisher_is_pinned`.
3. Publish that build and update a test PC through both paths: the desktop Update button and Admin's `update_rpcd`.
   Then confirm an unsigned Setup is refused before it starts (the agent log shows the publisher error).

A PC accepts only signed updates from then on. Signing must stay on for every release, and changing the identity
validation or certificate profile changes the identity EKU, so ship a build with the new pin before switching.

Not covered yet: the Agent EXE and app EXE inside the packages, and the Setup uninstaller, are not signed. The
Microsoft Store Win32 listing needs those too.
