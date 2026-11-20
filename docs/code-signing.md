# Test code signing

This signs RPCD builds for five test laptops. The certificate is self-signed. Windows trusts it only on a PC where its public half has been installed. Customer PCs stay as they are. The installer does not install a certificate or a trusted root.

## Create the certificate

On your own Windows PC (not in CI):

```powershell
pwsh -NoProfile -File scripts/signing/New-RpcdTestSigningCert.ps1
```

The script prompts for a password. Leave the password off the command line so it does not land in shell history.

It creates a code-signing certificate with the Code Signing EKU (`1.3.6.1.5.5.7.3.3`), RSA 3072, SHA-256, and five years of validity. Pass `-Years 3` through `-Years 5`, or `-KeyLength 4096`. The default subject is:

```text
CN=Remote PC Diagnostics Test Code Signing
```

Pass `-Subject 'CN=Your Subject'` to use another subject. The MSIX `Package/Identity/Publisher` has to be that exact string. CI copies it from the certificate when the secrets below are set.

Files land in `artifacts/signing/` (gitignored):

| File | What it is |
| --- | --- |
| `rpcd-test-codesign.pfx` | Private key. Never commit it. |
| `rpcd-test-codesign.pfx.b64` | One-line base64 of the PFX. This is the secret value. Never commit it. |
| `rpcd-test-codesign.cer` | Public certificate. Safe to publish. |

`*.pfx` and `*.pfx.b64` are gitignored anywhere in the tree. Copy the base64 onto the clipboard with the command the script prints:

```powershell
Get-Content -Raw artifacts/signing/rpcd-test-codesign.pfx.b64 | Set-Clipboard
```

Optional: copy only the `.cer` to `scripts/signing/rpcd-test-codesign.cer` and commit that public file. CI also attaches `rpcd-test-codesign.cer` to the GitHub release once signing is turned on.

The private key remains in `Cert:\CurrentUser\My` on the PC that created it. Remove that copy later if the PFX should be the only one.

## GitHub secrets

Add both under Settings → Secrets and variables → Actions → New repository secret.

| Secret | Value |
| --- | --- |
| `WINDOWS_CODESIGN_PFX_BASE64` | The single line in `rpcd-test-codesign.pfx.b64` |
| `WINDOWS_CODESIGN_PFX_PASSWORD` | The PFX password |

There is no secret for the public certificate. A base64 PFX of this size is a few kilobytes, under GitHub's secret size limit. Surrounding whitespace on the password secret is ignored.

When both secrets are unset, each signing step logs `Code signing skipped` and the packages stay unsigned, so current builds keep working. When only one of the two is set, the build fails instead of shipping a half-configured signature.

## What CI signs

`.github/workflows/ci.yml` reaches the signer through the installer, TestShop, Agent MSI, and MSIX scripts (`scripts/signing/Invoke-RpcdCodeSign.ps1`).

Signed before packaging, so the installer, MSI, and MSIX contain signed binaries:

- `RemotePCDiagnostics*.exe` and `RemotePCDiagnostics*.dll` in the publish folder (Host, Agent, MemTest, ModuleHost, ModuleUiHost, and the bundled module DLLs)

osquery, HardeningKitty, and the .NET runtime files are left alone.

Signed after packaging, and only then hashed:

- `RemotePCDiagnostics-Setup-*-win-x64.exe`
- `RemotePCDiagnostics-TestShop-Setup-*-win-x64.exe`
- `RemotePCDiagnostics.Agent-*-win-x64.exe` (also signed before WiX packs the MSI)
- `RemotePCDiagnostics.Agent-*-win-x64.msi`
- `RemotePCDiagnostics-*-win-x64.msix`

The signer runs:

```text
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f <pfx> /p <password> <files>
signtool verify /pa /v <file>
```

If the DigiCert timestamp server fails, it tries `http://timestamp.sectigo.com`. The password is passed to signtool and is not written into the log. On the GitHub-hosted runner, the job imports the public certificate into that runner's certificate stores first, because `signtool verify /pa` checks the chain and a self-signed certificate is otherwise untrusted there. That import is the ephemeral runner. The installer does not do it.

### MSIX publisher

Windows installs a signed MSIX only when `Package/Identity/Publisher` equals the certificate subject ([Sign your MSIX package](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide)).

When the PFX secrets are present and the `msix_publisher` workflow input and the `MSIX_PUBLISHER` repository variable are both unset, the MSIX build sets Publisher to the certificate subject. For the default certificate that is `CN=Remote PC Diagnostics Test Code Signing`.

When either override is set, it has to be that same subject or the MSIX job fails. For these test laptops, leave `MSIX_PUBLISHER` unset. A test-signed MSIX is for sideload on those laptops. Partner Center still expects the Store publisher identity, so submit an unsigned Store package there, produced with the secrets unset.

## Trust it on each test laptop

Repeat these steps on each laptop. Use the public `.cer` only. Do not copy the PFX to the laptops.

1. Download `rpcd-test-codesign.cer` from the GitHub release, or take the file the create script wrote. Compare its thumbprint with the one the create script printed.
2. Open PowerShell as Administrator.
3. Run:

```powershell
pwsh -NoProfile -File scripts/signing/Install-RpcdTestCert.ps1 -CerPath C:\path\to\rpcd-test-codesign.cer
```

If the `.cer` is at `scripts/signing/rpcd-test-codesign.cer` or `artifacts/signing/rpcd-test-codesign.cer`, `-CerPath` can be omitted.

The script imports that one certificate into:

| Store | Why |
| --- | --- |
| LocalMachine Trusted Publisher | Authenticode treats this publisher as trusted on this PC. |
| LocalMachine Trusted Root | The self-signed chain ends in a trusted root, which is what lets the signature verify. This makes the certificate a trust anchor on this PC. |
| LocalMachine Trusted People | The store App Installer checks for a sideloaded MSIX. Microsoft's current guidance is to import a self-signed package certificate here, and calls Trusted Root the alternative it does not recommend for a general-purpose PC ([App Installer troubleshooting](https://learn.microsoft.com/en-us/windows/msix/app-installer/troubleshoot-appinstaller-issues), [MSIX troubleshooting](https://learn.microsoft.com/en-us/windows/msix/msix-troubleshooting-guide)). These five laptops are the place the root is installed, on purpose. |

4. Download the setup EXE or the MSIX from the same release.
5. A browser download carries Mark of the Web. Clear it, or SmartScreen can still warn:

```powershell
Unblock-File -LiteralPath .\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe
```

The file's Properties dialog has the same Unblock checkbox. A copy over USB or a local share does not add Mark of the Web.

6. Run the installer, or sideload with `Add-AppxPackage .\RemotePCDiagnostics-*-win-x64.msix`.

Remove the certificate from that laptop (the same thumbprint only; other roots stay):

```powershell
pwsh -NoProfile -File scripts/signing/Install-RpcdTestCert.ps1 -Uninstall -CerPath C:\path\to\rpcd-test-codesign.cer
```

## Caveats

- Trust exists only on the PCs where the script was run. Every other PC still shows an untrusted signature. Keep the certificate off customer PCs. The installer has no step that adds a root.
- SmartScreen can still warn for a downloaded file until Mark of the Web is cleared. A self-signed certificate does not build SmartScreen reputation. Unblock the file on the test laptop after download.
- The PFX and `WINDOWS_CODESIGN_PFX_PASSWORD` sign any code these laptops will trust. Keep them in GitHub secrets. If they leak, run `-Uninstall` on each laptop and create a new certificate.
- Putting this certificate in Trusted Root is broader than MSIX needs. On these laptops that is intentional. Uninstall removes it from Trusted Root, Trusted Publisher, and Trusted People together.
