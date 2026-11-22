# Pluggable BIOS Update Provider Contract

This document defines the contract for implementing vendor-specific BIOS/UEFI update providers in `RemotePCDiagnostics`.

## Architecture Overview

- **Public contract (`RemotePCDiagnostics.Abstractions`)** — zero dependency on `Core`, `Host`, or `UI`:
  - `src/RemotePCDiagnostics.Abstractions/Bios/IBiosUpdateProvider.cs`
  - `src/RemotePCDiagnostics.Abstractions/Bios/BiosModels.cs`
- **Vendor-independent orchestration & helpers (`RemotePCDiagnostics.Core/Bios/`)**:
  - `BiosUpdateService` (`IBiosUpdateService`) — discovers all registered `IBiosUpdateProvider` instances, orders them by descending `Priority` (then `VendorId`), resolves the best match for the current PC, and enforces approval & pre-flash safety gates before delegating to `InstallAsync`.
  - `DefaultBiosSystemProbe` (`IBiosSystemProbe`) — reads Windows SMBIOS registry (`HKLM\HARDWARE\DESCRIPTION\System\BIOS`), firmware mode (`UEFI`/`Legacy`), and osquery (`system_info`, `platform_info`).
  - `DefaultBiosInstallSafetyProbe` (`IBiosInstallSafetyProbe`) — probes AC power, battery charge %, BitLocker state, elevation, and pending reboot markers.
  - `BiosInstallSafetyEvaluator` — deterministic safety gates (explicit approval, elevation, AC power + ≥30% battery when battery is present, BitLocker suspension guard, pending reboot guard, HTTPS-only URL).
  - `BiosVersionComparer` — compares dotted numeric (`1.9` vs `1.14.0`), letter-prefixed (`F.8` vs `F.24`, `A09` vs `A12`), skeleton-matched (`N32ET89W` vs `N32ET91W`), and `DateOnly` release dates.
  - `BiosPackageVerifier` — strict HTTPS + optional vendor host-suffix validation (`IsSafeDownloadUrl`) and constant-time SHA-256 verification (`VerifyFileSha256Async`).
  - `BiosServiceCollectionExtensions` — `AddBiosUpdates()` and `AddBiosUpdateProvider<TProvider>()`.

## Implementing a Vendor Provider

Implement `IBiosUpdateProvider` (namespace `RemotePCDiagnostics.Core.Bios`):

| Member | Convention / Requirement |
| --- | --- |
| `VendorId` | Stable lowercase identifier: `"hp"`, `"dell"`, `"lenovo"`, `"asus"`, `"acer"`, `"msi"`, `"microsoft"`, `"framework"`, `"windows-update"`. |
| `DisplayName` | Operator-facing name: `"HP"`, `"Dell"`, `"Lenovo"`, `"ASUS"`, `"Acer"`, `"MSI"`, `"Microsoft Surface"`, `"Framework"`, `"Windows Update"`. |
| `Priority` | `100` (default) for OEM-specific providers; `10` for generic fallbacks (e.g., Windows Update UEFI capsule). |
| `Capabilities` | Declare accurate `CanCheckLatest`, `CanInstall`, `SupportsSilentInstall`, `RequiresReboot`, `RequiresElevation`, `RequiresInternet`. |
| `CanHandle(BiosSystemIdentity)` | **Fast, offline, never throws.** Match on `Manufacturer` and/or `BoardManufacturer` (and `Model`/`BoardProduct` where needed). Do not make network calls or spawn processes here. |
| `GetCurrentVersionAsync(BiosSystemIdentity, CancellationToken)` | Default returns `system.CurrentBios with { ProviderId = VendorId }`. Override only when the vendor needs normalized version/family extraction (e.g., HP BIOS family / SystemId from `BoardProduct`, Lenovo version prefix). |
| `GetLatestVersionAsync(BiosSystemIdentity, BiosCurrentInfo, CancellationToken)` | Query the vendor catalog/API/tool and return `BiosLatestInfo` using factory helpers (`UpToDate`, `UpdateAvailable`, `Unsupported`, `Unavailable`, `Offline`, `Failed`). Use `BiosVersionComparer.IsNewer(...)` or vendor-specific comparison. |
| `InstallAsync(BiosInstallRequest, IProgress<BiosInstallProgress>?, CancellationToken)` | Optional (`Capabilities.CanInstall`). Download to a temp or `request.StagingDirectory` path, verify integrity, suspend BitLocker if needed and requested, stage/flash silently, report `BiosInstallProgress`, and return `BiosInstallResult`. |

### Where to Place Vendor Providers & How to Register

- Built-in vendor providers live under `src/RemotePCDiagnostics.Core/Bios/Providers/` (e.g., `HpBiosUpdateProvider.cs`, `DellBiosUpdateProvider.cs`, `LenovoBiosUpdateProvider.cs`, etc.).
- Register each provider via `services.AddBiosUpdateProvider<TProvider>()` in `src/RemotePCDiagnostics.Host/HostServices.cs` (or in an `IModulePlugin.RegisterServices` implementation for external plugins).
- Do **not** modify `IBiosUpdateService`, `BiosUpdateService`, or `IBiosUpdateProvider` unless strictly necessary for a general capability.

## Security & Safety Requirements (Mandatory)

1. **HTTPS & Host Allowlist:** Validate every download URL with `BiosPackageVerifier.IsSafeDownloadUrl(url, allowedHostSuffixes)` restricted to official vendor domains (e.g., `["hp.com", "hpcloud.hp.com"]`, `["dell.com"]`, `["lenovo.com"]`, etc.).
2. **Package Integrity:** If `request.Target.Sha256` is present and `request.VerifyHash` is `true`, verify the downloaded file with `BiosPackageVerifier.VerifyFileSha256Async(...)` before execution. When a vendor catalog does not publish SHA-256, verify Authenticode signature before executing any downloaded installer.
3. **No Command Injection:** Never invoke a command shell (`cmd.exe`, `powershell.exe`, `pwsh`, `bash`) and never interpolate SMBIOS strings (`Model`, `BoardProduct`, `SystemSku`, URLs, file paths) into command strings. Pass arguments exclusively via `ProcessStartInfo.ArgumentList` / parameterized command APIs (`SystemCommandRunner.RunAsync`) and validate strict character allowlists (e.g., 4-hex HP SystemId `^[0-9A-Fa-f]{4}$`).
4. **Never Log Secrets / PII:** Do not log `BiosSystemIdentity.SerialNumber`.
5. **Honor Request Flags:**
   - Do **not** trigger an automatic system restart unless `request.AllowReboot` is `true`. Prefer staging the update (`BiosInstallResult.StagedForReboot(...)`) so the operator controls reboot timing.
   - Honor `request.SuspendBitLocker` (e.g., suspend for 1 reboot by invoking `manage-bde.exe` directly via `ArgumentList` with `["-protectors", "-disable", drive, "-RebootCount", "1"]` where `drive` matches `^[A-Za-z]:$`, defaulting to `C:`, or via a vendor CLI flag) and set `BitLockerSuspended = true` on `BiosInstallResult` when suspended.
6. **Never Bypass `BiosUpdateService`:** All UI/workflow callers must call `IBiosUpdateService`, never `IBiosUpdateProvider.InstallAsync` directly.
7. **Timeout & Cancellation:** Propagate `CancellationToken` to all HTTP and process calls and enforce bounded timeouts.
8. **Pure C# Only — No PowerShell or Shell Scripts:** Implement all vendor catalog lookups, XML/JSON/ZIP/CAB parsing, Authenticode verification (`WinVerifyTrust`), BitLocker state probing (`Shell.Application` COM / `System.Management` WMI), and Windows Update Agent queries (`Microsoft.Update.Session` COM) in 100% pure C#. Do **not** use PowerShell (`.ps1`, `powershell.exe`, `pwsh`, `RunPowerShellAsync`, HPCMSL) or shell scripts (`cmd.exe`, `.bat`, `.cmd`, `bash`, `.sh`). When invoking native Windows executables (`manage-bde.exe`, `msiexec.exe`, `pnputil.exe`, `dcu-cli.exe`, vendor `.exe` installers), launch the binary directly via `ArgumentList` only.
9. **Agent Elevation Span for Admin BIOS Operations:** `RemotePCDiagnostics.Host` normally runs as a standard user (`asInvoker`) and NEVER self-elevates. When `!IsProcessElevated`, privileged BIOS operations (BitLocker 1-reboot suspension, verified BIOS installer execution, and Windows Update firmware capsule installation) MUST route over the named-pipe `IElevatedCommandBridge` to `RemotePCDiagnostics.Agent` (running as Administrator/SYSTEM) rather than attempting to elevate in-process. On the Agent side, enforce a strict security boundary: never accept arbitrary paths or arbitrary command lines — reject UNC/network paths and shell metacharacters, copy the package into an admin-owned staging directory (eliminating TOCTOU), independently re-verify SHA-256 (when provided) and Authenticode signature or an allowlisted vendor tool path (`%ProgramFiles%`), and validate arguments against a strict per-vendor/per-mode allowlist (`UseShellExecute = false`, `ArgumentList` only, pure C#).
10. **Pinned signers in the Agent:** a valid Authenticode signature is not enough. The Agent checks revocation and requires the signing certificate's organization (O=) to match the vendor for that install mode (`BiosAgentInstallModes.AllowedSignerOrganizations`); capsule catalogs (`.cat`) must be signed by Microsoft. Add the vendor's exact O= value there when adding an install mode.
11. **BitLocker failure stops the flash:** check `BiosBitLockerSuspendOutcome.BlocksInstall`, not just `ElevationRequired`. Suspension that doesn't apply is only OK when `BiosInstallRequest.BitLockerKnownOff` is true (`BiosUpdateService` sets it from the safety probe).
12. **Long Agent operations are jobs:** `bios_run_installer` and `bios_install_wua` answer at once with a `biosJobId` when they take more than a few seconds, and the app polls `bios_job_status`, so other Agent requests keep flowing. A request for the same package or the same Windows Update while one runs joins that job. Cancelling on the app side only stops the waiting; a started flash is never interrupted.

## Target Vendor Matrix

| Vendor | `VendorId` | Priority | Typical Identity Fields | Typical Backend |
| --- | --- | --- | --- | --- |
| HP | `hp` | 100 | `Manufacturer` (`HP`/`Hewlett-Packard`), `BoardProduct` (4-hex SystemId) | HP SoftPaq / HP HTTPS catalog (pure C# HTTP + XML/CAB) |
| Dell | `dell` | 100 | `Manufacturer` (`Dell`), `SystemSku` (4-hex System ID) | Dell Catalog (`CatalogPC.cab` via pure C# HTTP/CAB, or direct `dcu-cli.exe` via `ArgumentList`) |
| Lenovo | `lenovo` | 100 | `Manufacturer` (`Lenovo`), `Model` (4-char MTM prefix) | Lenovo Update Retriever / Commercial Vantage XML catalog |
| ASUS | `asus` | 100 | `Manufacturer` (`ASUSTeK`/`ASUS`), `Model`/`BoardProduct` | ASUS Support API / EZ Update |
| Acer | `acer` | 100 | `Manufacturer` (`Acer`), `Model` | Acer Support catalog |
| MSI | `msi` | 100 | `Manufacturer` (`Micro-Star`/`MSI`), `BoardProduct`/`Model` | MSI Support API |
| Microsoft Surface | `microsoft` | 100 | `Manufacturer` (`Microsoft Corporation`), `Model` (`Surface*`) | Windows Update / Surface MSI catalog |
| Framework | `framework` | 100 | `Manufacturer` (`Framework`), `Model`/`BoardProduct` | LVFS / Framework release metadata |
| Windows Update (Fallback) | `windows-update` | 10 | Any UEFI system (`FirmwareMode == Uefi`) | Windows Update Agent COM (`Microsoft.Update.Session` in pure C# — `Driver` / `System Firmware` capsule) |

## Testing Checklist for Every Vendor Provider

Each vendor provider must ship with offline unit tests (no live network calls in CI) covering:

- `CanHandle` returns `true` for known manufacturer/board spellings and `false` for other OEMs / empty identity.
- `GetCurrentVersionAsync` normalization (if overridden).
- `GetLatestVersionAsync`:
  - `UpdateAvailable` when catalog version is newer (verifies version, date, download URL, SHA-256/package ID).
  - `UpToDate` when current version matches or exceeds catalog version.
  - `UnsupportedHardware` / `ProviderUnavailable` / `Offline` / `Failed` edge cases (HTTP error, malformed payload, unknown model/SystemId).
- `InstallAsync` (if `Capabilities.CanInstall == true`):
  - Rejects non-HTTPS / non-vendor URLs and SHA-256 mismatches.
  - Reports `BiosInstallProgress` stages and returns `StagedForReboot` / `Completed` without rebooting when `AllowReboot == false`.
  - Handles non-zero installer exit codes cleanly without throwing.
- Pure C# compliance: zero PowerShell or shell script invocations (all catalog/archive/WUA logic in C#, native binaries invoked via `ArgumentList` only).
- Agent elevation span (for install-capable providers): un-elevated host with a connected `IElevatedCommandBridge` routes BitLocker suspension, verified installer execution, and WUA firmware installs through the Agent; un-elevated host without a connected bridge fails cleanly with an elevation error; Agent-side validation rejects tampered SHA-256, UNC paths, disallowed arguments, and unverified executables.
