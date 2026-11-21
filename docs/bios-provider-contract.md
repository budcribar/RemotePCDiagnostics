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
3. **No Command / Shell Injection:** Never interpolate SMBIOS strings (`Model`, `BoardProduct`, `SystemSku`, URLs, file paths) into shell or PowerShell strings. Pass arguments via `ArgumentList` / parameterized command APIs or validate strict character allowlists (e.g., 4-hex HP SystemId `^[0-9A-Fa-f]{4}$`).
4. **Never Log Secrets / PII:** Do not log `BiosSystemIdentity.SerialNumber`.
5. **Honor Request Flags:**
   - Do **not** trigger an automatic system restart unless `request.AllowReboot` is `true`. Prefer staging the update (`BiosInstallResult.StagedForReboot(...)`) so the operator controls reboot timing.
   - Honor `request.SuspendBitLocker` (e.g., suspend for 1 reboot via `manage-bde -protectors -disable C: -RebootCount 1` or vendor CLI flag) and set `BitLockerSuspended = true` on `BiosInstallResult` when suspended.
6. **Never Bypass `BiosUpdateService`:** All UI/workflow callers must call `IBiosUpdateService`, never `IBiosUpdateProvider.InstallAsync` directly.
7. **Timeout & Cancellation:** Propagate `CancellationToken` to all HTTP and process calls and enforce bounded timeouts.

## Target Vendor Matrix

| Vendor | `VendorId` | Priority | Typical Identity Fields | Typical Backend |
| --- | --- | --- | --- | --- |
| HP | `hp` | 100 | `Manufacturer` (`HP`/`Hewlett-Packard`), `BoardProduct` (4-hex SystemId) | HP SoftPaq / HPCMSL / HP FTP catalog |
| Dell | `dell` | 100 | `Manufacturer` (`Dell`), `SystemSku` (4-hex System ID) | Dell Catalog (`CatalogPC.cab` / DCU CLI) |
| Lenovo | `lenovo` | 100 | `Manufacturer` (`Lenovo`), `Model` (4-char MTM prefix) | Lenovo Update Retriever / Commercial Vantage XML catalog |
| ASUS | `asus` | 100 | `Manufacturer` (`ASUSTeK`/`ASUS`), `Model`/`BoardProduct` | ASUS Support API / EZ Update |
| Acer | `acer` | 100 | `Manufacturer` (`Acer`), `Model` | Acer Support catalog |
| MSI | `msi` | 100 | `Manufacturer` (`Micro-Star`/`MSI`), `BoardProduct`/`Model` | MSI Support API |
| Microsoft Surface | `microsoft` | 100 | `Manufacturer` (`Microsoft Corporation`), `Model` (`Surface*`) | Windows Update / Surface MSI catalog |
| Framework | `framework` | 100 | `Manufacturer` (`Framework`), `Model`/`BoardProduct` | LVFS / Framework release metadata |
| Windows Update (Fallback) | `windows-update` | 10 | Any UEFI system (`FirmwareMode == Uefi`) | Windows Update Agent (`Driver` / `System Firmware` capsule) |

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
