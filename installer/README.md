# Remote PC Diagnostics — Windows Installer (Inno Setup)

Builds a single-file Windows `x64` setup wizard (`RemotePCDiagnostics-Setup-<Version>-win-x64.exe`) that installs **Remote PC Diagnostics** into `C:\Program Files\RemotePCDiagnostics`.

## What the Installer Does

- **Self-contained multi-file layout**: Publishes `RemotePCDiagnostics.Host.exe`, `RemotePCDiagnostics.MemTest.exe`, `RemotePCDiagnostics.ModuleHost.exe`, `moduleui\RemotePCDiagnostics.ModuleUiHost.exe`, all 24 bundled diagnostic modules (`builtin-modules\`), `osqueryi.exe`, and `HardeningKitty` into `C:\Program Files\RemotePCDiagnostics` (with empty `modules\` and `checks\` plugin folders ready for signed extensions). No separate .NET 10 installation is required on target PCs.
- **Shortcuts**: Creates a **Start Menu** shortcut (`Remote PC Diagnostics`) and offers an optional **Desktop** shortcut checkbox during setup. Both shortcuts, and the "launch now" box at the end of setup, start a remote session shared with a remote user, with voice (`-u=https://remoteblazorwebview.com:34544 --mirror --voice`; the `RemoteParameters` line in `RemotePCDiagnostics.iss`). Running `RemotePCDiagnostics.Host.exe` with no arguments starts it in Local mode.
- **Microsoft Edge WebView2 Runtime check & bootstrapper**: Checks `HKLM` / `HKCU` EdgeUpdate registry keys for the Evergreen WebView2 Runtime (`{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`). If missing, automatically downloads and silently installs `MicrosoftEdgeWebview2Setup.exe` (or uses a local `MicrosoftEdgeWebview2Setup.exe` placed alongside the Setup `.exe` for offline installs).
- **Safe in-place upgrades**: Uses `AppMutex=Global\RemotePCDiagnostics.Host` (`CloseApplications=yes`) to detect a running instance before overwriting files, and preserves `%ProgramData%\RemotePCDiagnostics` history/undo state across upgrades.
- **Clean uninstall**:
  - Removes any leftover `"Remote PC Diagnostics - continue service workflow"` scheduled task and `RemotePCDiagnosticsResume` `RunOnce` entry.
  - On interactive uninstall, asks whether to also delete saved diagnostic logs, benchmark history, preferences, and undo state under `%ProgramData%\RemotePCDiagnostics` and `%LOCALAPPDATA%\RemotePCDiagnostics` (defaults to **No** so history/undo records aren't accidentally wiped).

## Building Locally on Windows

### Prerequisites
1. **.NET 10 SDK** (`10.0.x`)
2. **Inno Setup 6** (`ISCC.exe`):
   ```powershell
   winget install --id JRSoftware.InnoSetup -e
   ```
3. Either the local `PeakSWC.RemoteBlazorWebView.*` `.nupkg` files in `third_party/RemoteBlazorWebView/packages`, or a sibling `..\RemoteBlazorWebView` checkout beside this repository (automatically detected by `Build-Installer.ps1`).

### Build Command
From the repository root:
```powershell
pwsh -NoProfile -File installer/Build-Installer.ps1
```

Outputs are written to `artifacts/installer/`:
- `RemotePCDiagnostics-Setup-<Version>-win-x64.exe`
- `RemotePCDiagnostics-Setup-<Version>-win-x64.exe.sha256`

## Rolling Pre-release (Single Copy, Replaced on Every Push to `main`)

Every push to `main` runs `.github/workflows/ci.yml`, deletes any previous GitHub pre-release (and its tag), and publishes a single fresh **`prerelease`** pre-release containing `RemotePCDiagnostics-Setup-<Version>-win-x64.exe` and its `.sha256` file so no historical pre-release clutter accumulates.

To build locally on Windows and immediately replace that same rolling pre-release via the GitHub CLI (`gh`):
```powershell
.\publish.ps1
```
*(Pass `-LocalOnly` to build locally without uploading, or `-IncludePortable` to also build and attach the single-file portable `.exe`.)*

## Silent / Unattended Deployment Flags

- **Silent install** (Start Menu shortcut only, auto-bootstraps WebView2 if missing):
  ```powershell
  .\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  ```
- **Silent install with Desktop shortcut**:
  ```powershell
  .\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /TASKS="desktopicon"
  ```
- **Skip WebView2 check** (e.g., pre-baked air-gapped image):
  ```powershell
  .\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SKIPWEBVIEW2
  ```
- **Silent uninstall (keep logs/history/undo state)**:
  ```powershell
  "C:\Program Files\RemotePCDiagnostics\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  ```
- **Silent uninstall AND purge `%ProgramData%\RemotePCDiagnostics` + `%LOCALAPPDATA%\RemotePCDiagnostics`**:
  ```powershell
  "C:\Program Files\RemotePCDiagnostics\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLEANSTATE
  ```
