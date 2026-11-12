# WinGet Package Manifests — `BudCribar.RemotePCDiagnostics.Agent`

This folder contains the multi-file Windows Package Manager (`winget`) manifest templates for **`RemotePCDiagnostics.Agent.exe`**, the standalone outbound Windows Service enrollment agent for Managed Service Providers (MSPs) and IT fleets:

- [`BudCribar.RemotePCDiagnostics.Agent.yaml`](BudCribar.RemotePCDiagnostics.Agent.yaml) — Version manifest
- [`BudCribar.RemotePCDiagnostics.Agent.installer.yaml`](BudCribar.RemotePCDiagnostics.Agent.installer.yaml) — Installer manifest (`InstallerType: exe`, `ElevationRequirement: elevationRequired`, silent `install` switches, and `namazso.PawnIO` dependency)
- [`BudCribar.RemotePCDiagnostics.Agent.locale.en-US.yaml`](BudCribar.RemotePCDiagnostics.Agent.locale.en-US.yaml) — Default `en-US` metadata, MIT license, and privacy policy URL

---

## Why `RemotePCDiagnostics.Agent` Ships Outside the Microsoft Store `.msix`

1. **Microsoft Store Policy `10.2.4` & `10.2.9` Compliance:** Store-packaged desktop apps (`RemotePCDiagnostics-*-win-x64.msix`) are designed for interactive user-initiated sessions (`asInvoker`) and must not silently register persistent `LocalSystem` unattended background agents or bundle third-party `.sys` kernel drivers.
2. **Clean MSP / RMM Deployment:** MSPs deploying across 25–500+ endpoints push `RemotePCDiagnostics.Agent.exe` silently as `SYSTEM` via NinjaOne, Syncro, Tactical RMM, Intune, or `winget` with tenant-scoped enrollment keys (`--server=... --key=rpd_live_...`).
3. **Optional WHQL Sensor Driver (`namazso.PawnIO`):** Declaring `namazso.PawnIO` under `PackageDependencies` gives MSP technician machines full CPU/motherboard temperature telemetry automatically via Microsoft's WHQL-signed driver package, while locked-down endpoints can bypass it anytime with `--skip-dependencies`.

---

## Silent RMM & CLI Usage

### Default interactive-consent install via `winget`
```powershell
winget install --id BudCribar.RemotePCDiagnostics.Agent --exact --silent --accept-package-agreements --accept-source-agreements
```

### Tenant-enrolled unattended MSP fleet install via `winget --override`
```powershell
winget install --id BudCribar.RemotePCDiagnostics.Agent --exact --override "install --server=https://relay.yourshop.com --key=rpd_live_YOUR_KEY --consent=unattended --lifetime=persistent" --accept-package-agreements --accept-source-agreements
```

### Skip optional `PawnIO` sensor driver on locked-down endpoints
```powershell
winget install --id BudCribar.RemotePCDiagnostics.Agent --exact --skip-dependencies --override "install --server=https://relay.yourshop.com --key=rpd_live_YOUR_KEY --consent=ask --lifetime=persistent"
```

### Check status or uninstall cleanly
```powershell
& "$env:ProgramFiles\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe" status
& "$env:ProgramFiles\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe" uninstall
```

---

## 1-Command `winget-pkgs` Submission Guide (Once Code Signing Is Active)

> **Prerequisite:** `microsoft/winget-pkgs` moderation requires standalone `.exe` installers to carry a valid Authenticode signature so SmartScreen / Defender validation passes cleanly. Submit to `winget-pkgs` right after activating either **SignPath Foundation** ($0 OSS code signing) or **Azure Artifact Signing** ($9.99/mo).

### 1. Validate manifests locally
```powershell
winget validate --manifest .\winget
```

### 2. Stamp the signed release URL + SHA-256 and open the PR to `microsoft/winget-pkgs`
Install `wingetcreate` (`winget install Microsoft.WingetCreate`), authenticate once (`wingetcreate token -s`), and run:

```powershell
# First-time submission (uses the YAML templates in .\winget and stamps the live release SHA-256):
$ver = "1.2.0"
$url = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v$ver/RemotePCDiagnostics.Agent-$ver-win-x64.exe"
$sha = (Invoke-WebRequest "$url.sha256" -UseBasicParsing).Content.Split(' ')[0].Trim().ToUpperInvariant()

(Get-Content .\winget\BudCribar.RemotePCDiagnostics.Agent.installer.yaml -Raw) `
  -replace 'InstallerUrl: .*', "InstallerUrl: $url" `
  -replace 'InstallerSha256: [0-9A-Fa-f]{64}', "InstallerSha256: $sha" |
  Set-Content .\winget\BudCribar.RemotePCDiagnostics.Agent.installer.yaml -NoNewline

winget validate --manifest .\winget
wingetcreate submit .\winget
```

For subsequent version bumps (`v1.2.1+`) once `BudCribar.RemotePCDiagnostics.Agent` is merged into `microsoft/winget-pkgs`:

```powershell
wingetcreate update BudCribar.RemotePCDiagnostics.Agent --version 1.2.1 --urls https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.2.1/RemotePCDiagnostics.Agent-1.2.1-win-x64.exe --submit
```
