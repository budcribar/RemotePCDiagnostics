# Potential Performance Improvements Backlog

## Workflow Goal
Provide a single checklist in the **Service Workflow** ([`WorkflowService.cs`](../src/RemotePCDiagnostics.Core/Workflow/WorkflowService.cs) / [`FixCatalog.cs`](../src/RemotePCDiagnostics.Core/Workflow/FixCatalog.cs)) where the technician or user simply checks the optimizations they want, and everything runs **100% unattended** with a **Pre and Post Benchmark** proving measurable gains across four pillars:
1. **Hard Drive Space & Storage Performance Improvements**
2. **RAM / Memory Improvements**
3. **Startup & App Launch Speed Improvements**
4. **Bloatware, Scheduled Tasks & Background Executables Removed (Pre/Post Inventory Counts)**

**Worktree cleanup exception:** Offer **Review unused agent worktrees and checkouts** as a separate, unchecked item. It requires folder selection and a second, explicit deletion approval during review before unattended execution. Selecting the item only opens the review; it does not authorize deletion. This is a planned feature, not an implemented executor.

---

## Part 1: Master Rankings (Sorted Two Ways)

### Ranking A — Sorted by Hard Drive Space Saved (Highest → Lowest)

| Rank | Item # | Optimization | Disk Space Saved (`BUDSLAPTOP` Measured) | RAM Saved | Default Mode |
| :---: | :---: | :--- | :---: | :---: | :--- |
| **1** | **[#1](#1-clean-developer-ai-agent--dot-folder-caches-nuget-143-gb-grok-99-gb-playwright-45-gb-temp-33-gb)** | **Clean Developer, AI Agent & Dot-Folder Caches** (`~/.grok` `9.86 GB`, `NuGet\v3-cache` `4.09 GB` + `1,005` superseded `~/.nuget/packages` versions `10.17 GB`, `Playwright` `4.50 GB`, `Temp` `3.30 GB`, `npm-cache` `707 MB`, `codex` `734 MB`, `Copilot` `394 MB`) | **`29.3 GB – 33.8 GB`** | — | **Auto-check caches only (including `14.26 GB` NuGet)**; Worktrees unchecked with separate approval (item 1a); Opt-in `ms-playwright` (`4.50 GB`) |
| **2** | **[#2](#2-clean-old-vs-code-commit-versions-30-gb-vsix-installer-cache-148-gb-new-outlook--onedrive-logscaches-89-gb-on-budslaptop)** | **Clean Old VS Code Commit Versions (`3.00 GB`), `CachedExtensionVSIXs` (`1.48 GB`), Claude `.vhdx.zst` (`1.25 GB`), OneDrive `ListSync`/Logs (`1.71 GB`), New Outlook `Olk` Caches (`808 MB`), Stale Classic `.ost` (`621 MB`), UWP `EBWebView` (`422 MB`), `CrashDumps` (`215 MB`)** | **`~8.92 GB`** | — | Auto-check dead versions/caches; Opt-in Classic `.ost` & `ListSync` |
| **3** | **[#3](#3-remove-pre-installed-oem--windows-consumer-store-bloatware-remove-appxpackage-factory-leftovers--disable-contentdeliverymanager-silent-re-installs-70-gb-on-budslaptop)** | **Remove Unsupported / OEM / Consumer Store Bloatware & Factory Leftovers** (`Clipchamp` `2.98 GB`, `PowerAutomateDesktop` `1.20 GB`, `Fidelity Trader+` `616 MB`, `Paint` AI `.onnxe` `417 MB`, `VidyoConnect` `411 MB`, `Lenovo\UserGuide` `399 MB`, `MicrosoftJournal` `323 MB`, `GetHelp`/`FeedbackHub` `351 MB`, `Mail & Calendar` `207 MB`, `Solitaire` `169 MB`, `BingNews` `158 MB`, `Todos` `75 MB`, `DropboxOEM` `60 MB`, `WindowsMaps` `43 MB`, `BingWeather` `30 MB`, `People` `24 MB`, `MixedReality` `18 MB`, `McAfee\WPS` `8 MB`, `Narrator` extensions, `DevHome`) | **`~7.05 GB`** | ~50–150 MB | **Auto-check** Unsupported (`Mail`, `Solitaire`, `Maps`, `People`, `DevHome`, `MixedReality`), No-Pen (`Journal`), & `Narrator`; Opt-in others |
| **4** | **[#4](#4-shrink-or-disable-chiberfilsys-567-gb-on-budslaptop-when-fast-startup--hibernate-is-not-used)** | **Shrink (`reduced`) or Disable (`off`) `C:\hiberfil.sys`** | **`2.84 GB – 5.67 GB`** | — | Opt-In |
| **5** | **[#5](#5-speed-up-vs-code-startup-by-pruning-duplicate-old-extensions--guid-staging-folders-in-vscodeextensions-127-gb)** | **Prune Duplicate Old Extensions & `.guid` Staging Folders in `~/.vscode/extensions`** (`4` superseded versions + `3` `.guid` folders) | **`1.27 GB`** (`1,266.6 MB`) | — | Auto-Check |
| **6** | **[#6](#6-prune-stale-chrome--edge-service-workercachestorage--code-cache-60-days-inactive-708-mb--262-gb)** | **Prune Stale Chrome & Edge `Service Worker\CacheStorage` & `Code Cache` (>60 Days Inactive)** | **`708 MB – 2.62 GB`** | — | Auto-Check (>60d old) |
| **7** | **[#7](#7-optimize-common-heavy-collaboration-pdf--media-apps-across-client-pcs-microsoft-teams-zoom-adobe-acrobat-slack-discord-spotify-steam)** | **Optimize Collaboration, PDF & Electron Apps** (`Zoom\asr` `172 MB` + `Grok Bot` `70 MB` on `BUDSLAPTOP`; up to `2.5 GB` dead Classic Teams + `1.5 GB` New Teams `EBWebView` on client PCs) | **`242 MB`** (`BUDSLAPTOP`)<br>**`500 MB – 3.5 GB`** (Client PCs) | **`450 MB – 1.5 GB`** (Client PCs) | Auto-check dead Classic Teams & >90d caches; Opt-in startup |
| **8** | **[#8](#8-remove--disable-unused-xbox-solitaire--gaming-subsystem-9-packages-5665-mb--gamedvr--gamebarpresencewriter--scheduled-task--4-services)** | **Remove / Disable Unused Xbox, Solitaire & Gaming Subsystem** (`9` Store packages + `GameDVR` + `GameBarPresenceWriter` + `4` Xbox services) | **`566.5 MB`** | **`~50–120 MB`** (stops `GameBarPresenceWriter` & `BcastDVR`) | Auto-check `Solitaire` & `MixedReality`; Opt-in full Xbox removal |
| **9** | **[#9](#9-interactive-brokers-trader-workstation-cjtstwsvmoptions-jvm-tuning--uninstall-unused-ibkr-desktop-cntws-4883-mb)** | **Uninstall Unused `IBKR Desktop` (`C:\ntws`) + Tune Trader Workstation (`C:\Jts\tws.vmoptions`)** | **`488.3 MB`** | Reduces JVM GC heap spikes | Opt-In |
| **10** | **[#10](#10-uninstall-brother-powerengage--lenovo-now-bloatware-4441-mb--disable-promotionalunlock-scheduled-tasks)** | **Uninstall `Lenovo Now` (`441.5 MB`) & `Brother PowerENGAGE` (`2.6 MB`) + Disable Unlock/Promo Tasks** | **`444.1 MB`** | Stops 6-hr `msiexec /f` & unlock spikes | Auto-Check |
| **11** | **[#12](#12-visual-studio--net-build-speed-automated-full-path-defender-exclusions-night-only-updates--cache-cleanup-178-mb)** | **Visual Studio & `.NET` Build Speed: Full-Path Defender Exclusions + Clean `WebView2Cache`** | **`178.0 MB`** | Reduces `MsMpEng.exe` (`380 MB`) build spikes | Opt-In |
| **12** | **[#13](#13-clean-stale-office-lock-files-and-reset-bloated-excel15xlb)** | **Clean Stale Office Lock Files and Reset Bloated Excel15.xlb** (`~$Normal.dotm`, `Excel15.xlb`) | **Remeasure after excluding recovery files** | — | Auto-Check |

---

### Ranking B — Sorted by RAM / Memory Saved (Highest → Lowest)

| Rank | Item # | Optimization | RAM / Memory Saved (`BUDSLAPTOP` Measured) | Disk Space Saved | Default Mode |
| :---: | :---: | :--- | :---: | :---: | :--- |
| **1** | **[#14](#14-shut-down-idle-wsl-2--ai-sandbox-virtual-machine-vmmem--543-mb-ws--410-gb-committed-on-budslaptop--set-ai-vm-services-to-manual)** | **Shut Down Idle WSL 2 / AI Sandbox VM (`vmmem`) & Set `CoworkVMService` / `CodexSandboxService` to `Manual`** | **`543 MB – 1.1 GB` Active WS**<br>**(`4.10 GB` Committed RAM)** | — | Auto-Check (when Docker not running) |
| **2** | **[#15](#15-expand-startup-app-detection-to-packaged-uwp--store-startup-tasks-appmodelsystemappdata--883-mb-active--122-gb-committed-ram)** | **Disable Unneeded Packaged UWP / Store Startup Tasks** (`Phone Link` + `CrossDevice` `650.5 MB`, `OpenAI.Codex` `134.7 MB`, `AMD Radeon Software` tray/overlay `64.3 MB` WS / `353.1 MB` Committed, `LenovoUtility` `33.5 MB`, `OfficeHub`) | **`232 MB – 883 MB` Active WS**<br>**(`571 MB – 1.22 GB` Committed)** | — | Opt-in per app (`Phone Link` ticked: opening it starts it as usual) |
| **3** | **[#7](#7-optimize-common-heavy-collaboration-pdf--media-apps-across-client-pcs-microsoft-teams-zoom-adobe-acrobat-slack-discord-spotify-steam)** | **Disable Auto-Start & Background Services for `Microsoft Teams` (`450–850 MB`), `Adobe Acrobat` (`200–350 MB`), `Spotify` / `Discord` / `Slack` (`300–650 MB` each)** | **`450 MB – 1.5+ GB` Active WS** *(on client PCs with these apps)* | `242 MB – 3.5 GB` | Opt-In for Startup; Auto-check Adobe services |
| **4** | **[#16](#16-disable-windows-11-taskbar-weathernews-widgets--start-feed-widgetboardexe--widgetserviceexe--microsoftstartfeedproviderexe--6-msedgewebview2exe--520-mb-ram)** | **Disable Windows 11 Taskbar Weather/News Widgets & Start Feed** (`WidgetBoard.exe` + `WidgetService.exe` + `MicrosoftStartFeedProvider.exe` + 6 `msedgewebview2.exe`) | **`~520 MB` Active WS** | ~65 MB | Auto-Check (or Opt-In if user uses Widgets) |
| **5** | **[#17](#17-turn-off-bing-web-search-in-the-start-menu-searchhostexe--6-msedgewebview2exe-processes--288371-mb-ram)** | **Turn Off Bing Web Search in the Start Menu** (`DisableSearchBoxSuggestions = 1` — stops `SearchHost.exe` from spawning 6 `msedgewebview2.exe` processes; Start menu searches local apps, files, and settings only) | **`~288 – 371 MB` Active WS** | — | Opt-In (or Auto-Check with clear local-only search note) |
| **6** | **[#18](#18-disable-copilot--optional-connected-experiences-in-office-user-selected-opt-in--150400-mb-ram)** | **Disable Copilot & Optional Connected Experiences in Office** (stops embedded `msedgewebview2.exe` child processes inside Word/Excel/Outlook) | **`~150 – 400 MB` Active WS** *(while Office apps run)* | — | Opt-In |
| **7** | **[#19](#19-stop-secondary-non-default-browser-from-running-in-the-background-user-selected-opt-in--150300-mb-ram)** | **Stop Secondary (Non-Default) Browser (`Edge`) Startup Boost & Background Mode** | **`~150 – 300 MB` Active WS** | — | Opt-In (only for non-default browser) |
| **8** | **[#20](#20-expand-servicecandidates--uninstaller-targets-for-lenovo-notifyme-telemetry--brother-background-daemons-150-mb-active--394-mb-committed-ram)** | **Stop OEM Telemetry (`UDCService` / `NotifyMe` `58.7 MB` WS / `238.5 MB` Committed), 5 Brother Daemons (`46.4 MB`), `SQLWriter` (`6.6 MB`), & Optional `LenovoFnAndFunctionKeys` (`33.5 MB` WS / `83.7 MB` Committed)** | **`~150 MB` Active WS**<br>**(`~394 MB` Committed RAM)** | ~25 MB | Auto-check `UDCService`, Brother, `SQLWriter`; Opt-in `LenovoFnAndFunctionKeys` |
| **9** | **[#21](#21-expand-startup-app-detection-to-hklmrun-wow6432noderun-and-browser---no-startup-window-entries-100250-mb-ram)** | **Disable `HKLM\...\Run`, `WOW6432Node\...\Run` (4 Brother Startup Apps) & Browser `--no-startup-window` Keys** | **`~100 – 250 MB` Active WS** | — | Opt-in per startup item |
| **10** | **[#22](#22-programmatically-block-selected-heavy--unused-browser-extensions-extensioninstallblocklist--50150-mb-ram-per-extension)** | **Block Selected Heavy / Discontinued Browser Extensions (`PayPal Honey`, `MSN New Tab`, `Amazon Assistant`)** | **`~50 – 150 MB` Active WS** *(per active extension)* | ~46 MB | Opt-in per extension |
| **11** | **[#8](#8-remove--disable-unused-xbox-solitaire--gaming-subsystem-9-packages-5665-mb--gamedvr--gamebarpresencewriter--scheduled-task--4-services)** | **Disable Xbox `GameDVR` + `GameBarPresenceWriter.exe` WinRT Broker + 4 Xbox Services** | **`~50 – 120 MB` Active WS** *(when DirectX/OpenGL apps run)* | `566.5 MB` | Opt-In |
| **12** | **[#23](#23-skip-microsoft-office-start-screen-disableboottoofficestart--word-excel--powerpoint)** | **Skip Microsoft Office Start Screen (`DisableBootToOfficeStart = 1`)** | **`~15 – 40 MB` Active WS** *(+ 0.5–1.5s faster launch)* | — | Auto-Check |
| **13** | **[#24](#24-lock-default-printer-to-local-microsoft-print-to-pdf-on-pcs-with-networkwsd-printers--reschedule-officezoom-update-tasks-to-night-only)** | **Lock Default Printer to `Microsoft Print to PDF` + Reschedule Office/Zoom Tasks to Night-Only (`2:10 AM`)** | Eliminates daytime `sdxhelper` / `Zoom` spikes *(+ 2–10s faster Word/Excel launch)* | — | Auto-Check |

---

### Total Projected Savings Summary (`BUDSLAPTOP` Measured)

Historical estimates below are not a current scan. Tier 1 excludes worktrees. Tier 2 retains the historical all-options range only if worktree folders receive separate approval; selecting all general fixes is insufficient. Recompute totals from selected folders at review time.

| Optimization Tier | Total Hard Drive Space Freed | Total Active RAM Freed (Working Set) | Total Committed RAM Freed |
| :--- | :---: | :---: | :---: |
| **Tier 1 — Auto-Checked Safe Defaults Only** *(Zero workflow changes; includes `14.26 GB` NuGet Tier 1+2, Grok sessions/downloads only, `Temp`, dead VS Code versions/VSIXs/extensions, unsupported Store apps, `MicrosoftJournal` on no-pen PC, `Lenovo Now`, `PowerENGAGE`, idle WSL2 VM shutdown, Taskbar Widgets, Search Web Highlights, `UDCService`, Brother daemons)* | **`~40.1 GB`** (historical total less ~6.98 GB worktrees and ~0.33 GB removed Office cleanup) | **`1.47 GB – 1.55 GB`** | **`~5.50 GB`** |
| **Tier 2 — Auto-Checked + Opt-In (Worktrees Separately Approved)** *(Adds `ms-playwright` `4.50 GB`, Consumer Store apps `5.87 GB`, `hiberfil.sys` `2.84–5.67 GB`, `IBKR Desktop` `488 MB`, `OneDrive\ListSync` `1.46 GB`, Classic `.ost` `621 MB`, UWP Startup apps including `Phone Link` `650 MB`, Office Copilot, secondary browser background mode, Xbox subsystem)* | **`61.5 GB – 64.3 GB`** | **`1.88 GB – 2.74 GB`** | **`6.39 GB – 7.17 GB`** |

---

## Part 2: Pre/Post Benchmark & Report Metrics (`Phase 1 — Implemented ✅`)
[`Benchmarks.All`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs#L29-L46), [`BenchmarkRunner.cs`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkRunner.cs), [`WindowsBenchmarkProbes.cs`](../src/RemotePCDiagnostics.Host/WindowsBenchmarkProbes.cs#L149-L190), and [`ClientReport.cs`](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs#L51-L63) have been upgraded to capture and format all 4 pillars:

| Benchmark Pillar | Implemented Metric in [`BenchmarkModels.cs`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs) & [`WindowsBenchmarkProbes.cs`](../src/RemotePCDiagnostics.Host/WindowsBenchmarkProbes.cs) | What Moves It |
| :--- | :--- | :--- |
| **1. Hard Drive / Storage** | **`DiskFreeGb` (`Available Disk Space`, `HigherIsBetter`, formats as `"+41.2 GB freed"`)** alongside `DiskLatency` | Clearing `.grok` (`9.9 GB`), `%LOCALAPPDATA%\Temp` (`3.3 GB`), NuGet `v3-cache` + superseded packages (`14.26 GB`), `npm-cache` (`707 MB`), Playwright (`4.5 GB`), >60d Chrome & Edge `Service Worker` & `Code Cache` (`708 MB+`), dead VS Code versions/VSIXs/extensions (`5.75 GB`), `hiberfil.sys` (`2.8–5.7 GB`), and Store bloatware (`7.05 GB`). |
| **2. RAM / Memory** | **`MemoryUsedMb` (`Memory in Use`, formats as `"2000 MB freed (21% less)"`) & `BackgroundProcesses` (`Background Processes`, formats as `"18 fewer"`)** alongside `Paging` | Shutting down idle WSL2/Sandbox VMs (`543 MB` WS / `4.1 GB` Committed), disabling Win32 & UWP Startup apps (`Phone Link` `650 MB`, `Codex` `135 MB`, `AMD Radeon` `64 MB`, Brother/Lenovo tray apps), disabling Taskbar Widgets (`520 MB`), disabling Search Web Highlights (`288–371 MB`), stopping secondary browser Startup Boost (`150–300 MB`), blocking heavy browser extensions (`Honey`, `MSN New Tab`, `Amazon Assistant`), setting OEM/Brother services to Manual (`150 MB`). |
| **3. Startup & App Speed** | **`BootTime` (`Windows Boot Time`) + `ProgramStart` (`App Launch Latency`)** | Skipping Office Start Screen (`DisableBootToOfficeStart = 1`), locking Default Printer to `Microsoft Print to PDF`, cleaning stale template lock files, disabling Win32/UWP Startup apps, rescheduling logon/hourly tasks. |
| **4. Bloatware & Background Load Counts** | **Pre vs. Post Inventory Counts (`Weight = 0` so they never skew the speed score):**<br>• **`EnabledStartupApps`** (`Enabled Startup Apps`, `Win32` + `UWP`)<br>• **`AutoVendorServices`** (`Auto Third-Party Services`)<br>• **`ActiveScheduledTasks`** (`Active Third-Party Tasks`)<br>• **`InstalledBloatwareApps`** (`Bloatware Apps Installed`) | Uninstalling `Brother PowerENGAGE`, `Lenovo Now`, `Clipchamp`, `PowerAutomateDesktop`, `MicrosoftJournal`, `Solitaire`, `WindowsMaps`, `People`, `DevHome`, `MixedReality`, `Mail & Calendar`, `Narrator` extensions; removing/disabling `\PowerENGAGE`, `\Lenovo\LenovoNow*`, `\GoogleUserPEH\*`, `\SoftLanding\*`, `\Microsoft\Windows\Maps\*`, and `\Microsoft\Office\*Logon` tasks; disabling Win32/UWP startup apps and `Auto` background services. |

---

## Part 3: Detailed Catalog (Ordered by Hard Drive Space Saved, Then RAM Memory Saved)

### Section 1 — Ranked by Hard Drive Space Saved (Item IDs #1–#13; #11 retired)

#### 1. Clean Developer, AI Agent & Dot-Folder Caches (`NuGet` `14.3 GB`, `~/.grok` `9.9 GB`, `Playwright` `4.5 GB`, `Temp` `3.3 GB`)
* **Disk Space Saved:** Historical combined estimate **`29.3 GB – 33.8 GB`**, including worktrees. Worktree space is now a separate opt-in estimate and must be excluded from automatic cleanup totals.
* **Problem:** Developer, package, and AI agent dot-folders in `%USERPROFILE%` and `%LOCALAPPDATA%` grow into tens of gigabytes without automatic expiration.
  * On `BUDSLAPTOP` right now:
    * **`%USERPROFILE%\.grok` (historical measurement):** Contains **`6,979.6 MB (6.98 GB)`** in `worktrees`, **`2,483.8 MB (2.48 GB)`** in old `sessions`, and **`395.2 MB`** in `downloads`. Worktrees are project data; old timestamps do not prove they are orphaned or disposable. Review them separately under item 1a.
    * **NuGet (`21.16 GB` Total Across 2 Folders → `14.26 GB` Safely Removable — Auto-Checked):**
      * **Tier 1 — `%LOCALAPPDATA%\NuGet\v3-cache` (`4,086.8 MB` / `4.09 GB` — Auto-Checked):** Raw HTTP download cache (`dotnet nuget locals http-cache --clear`); never read again once packages are extracted into `.nuget\packages`.
      * **Tier 2 — Superseded Older Package Versions in `%USERPROFILE%\.nuget\packages` (`10,165.8 MB` / `10.17 GB` across `1,005` old version folders out of `567` packages — Auto-Checked Smart Prune):** Heavy packages have 2–8 old versions sitting alongside the newest version (`microsoft.playwright` 3 versions = `2.26 GB`, `microsoft.graph.beta` 2 versions = `1.39 GB`, `microsoft.netcore.app.runtime.win-x64` 8 versions = `1.05 GB`, `microsoft.windowsdesktop.app.runtime.win-x64` 8 versions = `1.04 GB`, `soenneker.libraries.ffmpeg` 2 versions = `809 MB`, `ilcompiler` 6 versions = `539 MB`). Even if an older project ever needed a pruned version later, Visual Studio / `dotnet restore` simply re-downloads that specific package automatically.
    * **`%LOCALAPPDATA%\ms-playwright` (`4,502.6 MB` / `4.50 GB`):** Downloaded Chromium/Firefox/WebKit test browsers.
    * **`%LOCALAPPDATA%\Temp` (`3,301.5 MB` / `3.30 GB`)**
    * **`%USERPROFILE%\.cache\codex-runtimes` (`1,732.7 MB`) + `%LOCALAPPDATA%\OpenAI\Codex\runtimes` (`241.6 MB`):** Contains 3 old `codex-primary-runtime.previous-*` backup folders (`336.6 MB`), `%USERPROFILE%\.codex\.tmp` and `cache` (`155.4 MB`), plus duplicate `241.6 MB` runtime binaries (`733.6 MB` cleanable).
    * **`%LOCALAPPDATA%\npm-cache` (`706.7 MB`)** (`_cacache` tarballs).
    * **`%LOCALAPPDATA%\Microsoft\Copilot\User Data\Default\Cache` (`394.1 MB`)**.
* **Automated Remediation:**
  * Clear `%LOCALAPPDATA%\Temp` files older than 24 hours (`3.30 GB`).
  * Clean `%USERPROFILE%\.grok\sessions` and `downloads` older than 30 days, plus `codex-primary-runtime.previous-*`, `.codex\.tmp`, and `Copilot` cache. Exclude `worktrees` from this automatic cache cleanup; use item 1a.
  * **NuGet Tier 1 + Tier 2 (`14.26 GB` — Auto-Checked):** Clear `%LOCALAPPDATA%\NuGet\v3-cache` & `NuGetScratch` (`4.09 GB`), clear `%LOCALAPPDATA%\npm-cache\_cacache` (>30d old, `706.7 MB`), and prune the `1,005` superseded older version folders in `%USERPROFILE%\.nuget\packages` (`10.17 GB`, keeping the newest version of each package + any version referenced in `%USERPROFILE%\source\repos\*\project.assets.json`).
  * Offer an opt-in checkbox for `%LOCALAPPDATA%\ms-playwright` (>60d old, `4.50 GB`).
* **NuGet detection corrected:** `NuGetCleanupScanner` uses `NuGet.Versioning` ordering rather than directory creation time. It retains the highest installed version and every package version referenced by recursively discovered `project.assets.json` files under `%USERPROFILE%\source\repos`. Package IDs and normalized versions are matched without case sensitivity. Unknown version folders are retained. Missing project roots, malformed/unreadable assets, or incomplete traversal disable the superseded-package estimate; the independent HTTP cache estimate remains available. Projects outside this root are not covered. This is detection only; package deletion remains Phase 3 work and must revalidate the same protections immediately before execution.

#### 1a. Review Unused Agent Worktrees and Checkouts (Opt-In, Separate Deletion Approval)

* **Default:** Unchecked. Global **Select all** must not approve worktree deletion or bypass its separate confirmation. All candidate folders also begin unchecked.
* **Decision:** Reject age-only automatic deletion. Use Git checks to explain what exists, then let the user decide which unused project copies may be discarded. A dirty checkout can still be unwanted; a clean checkout is not automatically disposable.
* **Discovery:** Scan known agent worktree locations, including `.grok/worktrees` and repository-local `.claude/worktrees`. Distinguish registered linked worktrees from standalone repositories and folders with broken Git metadata. Do not include the main project checkout automatically.
* **Review evidence:** Show the absolute path, project, branch or detached HEAD, estimated size, latest file write, tracked changes, untracked and ignored files, stashes, local-only commits, remote verification, active-session evidence, and unfinished Git operations. Report failed checks as unknown, never as clean or zero. Age is a sorting aid only.
* **Approval 1 — Select:** The user selects **Review unused agent worktrees and checkouts**, then individually selects folders from the evidence list. Selection alone schedules no deletion.
* **Approval 2 — Confirm deletion:** Show the exact paths and total estimated space with: **I confirm these selected project copies are unused and approve permanently deleting them, including any listed local changes or files not verified on the remote.** Require a separate unchecked confirmation and an explicit **Approve deletion of selected folders** action. Record the approved paths and disclosed findings before the unattended workflow begins. Confirmation applies only to those folders and that reviewed state; newly discovered folders never inherit approval.
* **Execution constraints:** Recheck paths, Git state, and active-session/operation status before deletion. Changed findings require renewed approval. Skip active, locked, inaccessible, or unresolved folders. Resolve broken Git metadata before offering deletion. Do not follow junctions or symlinks outside the approved folder. Preserve shared repository metadata and branches. Normally remove linked worktrees with `git worktree remove` without force; any discard requiring force must be specifically disclosed and approved. Standalone repository folders require their own explicit deletion handling.
* **Undo/reporting:** Deletion is irreversible unless an actual backup was made. Never claim that recreating a checkout restores deleted local files. Log deleted/skipped paths, reasons, and measured space reclaimed; exclude unapproved candidates from projected savings.
* **Local scan evidence (November 1, 2026):** Six project copies were found: two clean standalone Grok repositories (~3.60 GB combined), one Grok repository with 62 changed entries (~2.53 GB), one Grok linked worktree with a broken metadata path (~1.20 GB), and two Claude PageToMovie linked worktrees with modified local settings and ignored files (~6.67 GB combined). Clean repositories had no commits unique to local branches/tags relative to cached remote references, but live preservation was not established. The user identified these copies as unused. This supports user-directed cleanup with disclosed findings; it does not establish automatic eligibility or authorize this document change to delete them. Sizes are logical bytes, not guaranteed reclaimed disk space.
* **Implementation status:** Planned for Phase 3. The current storage scanner still groups Grok worktree bytes into the auto-checked `storage-grok` estimate; split that detection before wiring any cleanup executor. No worktree deletion was performed during the scan or this backlog update.

#### 2. Clean Old VS Code Commit Versions (`3.0 GB`), VSIX Installer Cache (`1.48 GB`), New Outlook & OneDrive Logs/Caches (`~8.92 GB` on `BUDSLAPTOP`)
* **Disk Space Saved:** **`~8.92 GB`**
* **Problem:** Several standard app folders accumulate gigabytes of dead versions, installers, and logs:
  * **`%LOCALAPPDATA%\Programs\Microsoft VS Code` (`4,291.2 MB` / `4.29 GB`):** Contains **5 full 750 MB commit-hash version folders** (`2c33b50b16`, `e646868227`, `a5b5009513`, `08d4889f9e`, `110a328ea5`) where **4 are dead older versions (`3,002.4 MB` / `3.00 GB`)** left behind by updates.
  * **`%APPDATA%\Code\CachedExtensionVSIXs` (`1,475.7 MB` / `1.48 GB`) + `Crashpad` (`70.2 MB`) + `Cache` (`84.9 MB`) + `CachedData` (`49.9 MB`) + `logs` (`37.9 MB`):** `1.72 GB` of already-extracted VS Code `.vsix` installers and crash/cache files.
  * **OneDrive (`%LOCALAPPDATA%\Microsoft\OneDrive` — `2.08 GB`):** `logs` (`252.4 MB` of `.odl` diagnostic logs) + `ListSync` (`1,455.3 MB` / `1.46 GB` synced by `Microsoft.Lists`).
  * **`%LOCALAPPDATA%\Claude-Data\*\vm_bundles\claudevm.bundle\rootfs.vhdx.zst` (`1,249.2 MB` / `1.25 GB`):** Leftover compressed `.zst` archive after `rootfs.vhdx` (`7.96 GB`) has already been extracted.
  * **New Outlook (`%LOCALAPPDATA%\Microsoft\Olk` — `1.62 GB`):** `EBWebView\Default\Service Worker` (`279.6 MB`), `Code Cache` (`204.7 MB`), `Cache` (`81.4 MB`), temp `Attachments` (`139.5 MB`), and `xpdApi.log` / `logs` (`103.1 MB`) = **`808.3 MB`** of cleanable cache/logs.
  * **Stale Classic Outlook `.ost` Offline Cache After Migrating to New Outlook (`620.5 MB` on `BUDSLAPTOP`):** When a user switches to New Outlook (`olk.exe`, evidenced by `NewOutlookMigration` and active `%LOCALAPPDATA%\Microsoft\Olk`), Classic Outlook's `.ost` cache (`%LOCALAPPDATA%\Microsoft\Outlook\budcribar@msn.com.ost`, `620.5 MB`, untouched since `8/22/2026`) sits orphaned on disk. *(Note: Only `.ost` offline server caches are targeted — never local `.pst` archives).*
  * **`%LOCALAPPDATA%\Packages\*\LocalState\EBWebView\Default\Cache` & `Code Cache` (`421.8 MB` in Clipchamp alone):** Embedded Edge WebView2 HTTP/bytecode caches inside UWP apps.
  * **`%LOCALAPPDATA%\CrashDumps` (`214.5 MB` across 10 `.dmp` files) & `C:\ProgramData\Microsoft\Windows\WER` (`6.9 MB`):** Old application crash memory dumps.
* **Automated Remediation:** Delete inactive commit folders in `Microsoft VS Code`, clear `CachedExtensionVSIXs` / `Crashpad` / `Cache` in `%APPDATA%\Code`, delete leftover `rootfs.vhdx.zst` when `rootfs.vhdx` exists, prune >30d logs/attachments/caches in `Microsoft\Olk` and `Microsoft\OneDrive\logs`, delete `.dmp` files in `%LOCALAPPDATA%\CrashDumps`, clear `EBWebView\Default\Cache` and `Code Cache` (>60d old), and offer opt-in checkboxes for the orphaned Classic `.ost` (`620.5 MB`) and `OneDrive\ListSync` (`1.46 GB`).

#### 3. Remove Pre-Installed OEM & Windows Consumer Store Bloatware (`Remove-AppxPackage`), Factory Leftovers & Disable `ContentDeliveryManager` Silent Re-Installs (`~7.05 GB` on `BUDSLAPTOP`)
* **Disk Space Saved:** **`~7.05 GB`** | **RAM Saved:** **`~50–150 MB`**
* **Problem:** OEM laptops and Windows 11 ship with unsupported/deprecated Store apps, multi-hundred-megabyte consumer apps (many stuffed with local `.onnxe` AI models), factory PDF manuals, leftover antivirus folders, and `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SilentInstalledAppsEnabled = 1` (which silently re-downloads promoted Store bloatware in the background):
  * **Auto-Checked by Default (Unsupported, Deprecated, or No Hardware Present — `785 MB`):**
    * **`Microsoft.MicrosoftJournal` (`322.8 MB` — Auto-Checked When No Pen Detected):** Tablet stylus handwriting app installed on a non-pen laptop. Extend [`WindowsMemorySystem.ReadDevices()`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L330-L360) / [`DeviceFacts`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs) with `HasPenDigitizer = (GetSystemMetrics(94) & 0x0C) != 0` (`SM_DIGITIZER`: `NID_INTEGRATED_PEN = 0x04 | NID_EXTERNAL_PEN = 0x08`). On `BUDSLAPTOP`, `SM_DIGITIZER = 193` (`IntegratedTouch = 1`, `IntegratedPen = 0`, `ExternalPen = 0`), so `Microsoft.MicrosoftJournal` is **auto-checked for removal**.
    * **`microsoft.windowscommunicationsapps` (`206.7 MB` — Unsupported / Auto-Checked):** Retired Windows 10/11 Mail & Calendar app (superseded by New Outlook `olk.exe`).
    * **`Microsoft.MicrosoftSolitaireCollection` (`169.4 MB` — Unsupported / Auto-Checked):** Unsupported pre-installed Solitaire & Casual Games bundle (`75.9 MB` app + `93.5 MB` ad cache).
    * **`Microsoft.WindowsMaps` (`43.0 MB`) + `MapsBroker` (`Auto` Service) + `\Microsoft\Windows\Maps\MapsToastTask` (`Ready` Task) — (Unsupported / Auto-Checked):** Deprecated by Microsoft (removed from Store in July 2025), yet the app, `Auto` service, and scheduled task are still active on `BUDSLAPTOP`.
    * **`Microsoft.People` (`23.7 MB` — Unsupported / Auto-Checked):** Deprecated standalone Windows People app.
    * **`Microsoft.MixedReality.Portal` (`18.0 MB` — Unsupported / Auto-Checked):** Deprecated Windows Mixed Reality VR portal.
    * **`Microsoft.Windows.DevHome` (`1.1 MB` — Unsupported / Auto-Checked):** Deprecated by Microsoft in May 2025.
    * **5 Removable Narrator Packages (`MicrosoftWindows.NarratorExtension-Word`, `NarratorExtension-ppt`, `NarratorExtension-OutlookWebApp`, `NarratorScript.Excel`, `NarratorScript.Outlook`) + `WinEnterLaunchEnabled = 0` (Auto-Checked When `RunningState == 0`):** Removes Narrator's Office/Web packages and disables the accidental `Win+Ctrl+Enter` launch shortcut.
    * **`C:\ProgramData\Lenovo\UserGuide` (`398.5 MB`) & `C:\Program Files\McAfee\WPS` (`7.8 MB` — Auto-Checked):** Factory multi-language PDF manuals (`7/13/2024`) and leftover `.deleted` McAfee trial files.
  * **Opt-In Consumer / OEM Store Apps (`~5.87 GB`):**
    * **`Clipchamp.Clipchamp` (`2,980.3 MB` / `2.98 GB` — `64.3 MB` app + `2,916 MB` in `%LOCALAPPDATA%\Packages`)**
    * **`Microsoft.PowerAutomateDesktop` (`1,196.4 MB` / `1.20 GB`)**
    * **`68D72461-B3DB-4FE2-AE47-50EF0FD7254F` (`Fidelity Trader+` — `616.4 MB`, untouched since `6/26/2026`)**
    * **`Microsoft.Paint` (`417.2 MB` — `352.8 MB` is bundled `.onnxe` AI models)**
    * **`VidyoConnect` (`411.0 MB` in `%LOCALAPPDATA%\VidyoConnect` — legacy `7/31/2025` video client + Outlook add-in)**
    * **`Microsoft.GetHelp` (`272.2 MB`) & `Microsoft.WindowsFeedbackHub` (`78.5 MB`)**
    * **`Microsoft.BingNews` (`158.1 MB`), `Microsoft.Todos` (`75.0 MB`), `C27EB4BA.DropboxOEM` (`59.9 MB`), `Microsoft.BingWeather` (`29.5 MB`)**
* **Automated Remediation:** Run `Remove-AppxPackage -AllUsers` and `Remove-AppxProvisionedPackage -Online` for selected packages, set `MapsBroker` to `Disabled`, disable `\Microsoft\Windows\Maps\MapsToastTask`, set `WinEnterLaunchEnabled = 0`, delete `Lenovo\UserGuide` and `McAfee\WPS`, and set `ContentDeliveryManager` flags (`SilentInstalledAppsEnabled`, `OemPreInstalledAppsEnabled`, `PreInstalledAppsEnabled`, `SoftLandingEnabled`, `SystemPaneSuggestionsEnabled`) to `0`.
* **Undo Support:** Restore `ContentDeliveryManager`, `Narrator`, and `MapsBroker` settings via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 4. Shrink or Disable `C:\hiberfil.sys` (`5.67 GB` on `BUDSLAPTOP`) When Fast Startup / Hibernate Is Not Used
* **Disk Space Saved:** **`2.84 GB – 5.67 GB`**
* **Problem:** `C:\hiberfil.sys` reserves **`5,672.6 MB` (`5.67 GB`)** on `C:\`. If the user disables Fast Startup (or only uses Sleep `S0 Modern Standby` and never uses Hibernate), that `5.67 GB` remains locked on the SSD.
* **Automated Remediation (Opt-In):** Run `powercfg /h /type reduced` (saves **`~2.84 GB`**) or `powercfg /h off` (saves the full **`5.67 GB`**).
* **Undo Support:** Run `powercfg /h on` / `powercfg /h /type full` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 5. Speed Up VS Code Startup by Pruning Duplicate Old Extensions & `.guid` Staging Folders in `~/.vscode/extensions` (`1.27 GB`)
* **Disk Space Saved:** **`1.27 GB`** (`1,266.6 MB`) | **Speed Gain:** Faster VS Code startup extension scan
* **Problem:** `%USERPROFILE%\.vscode\extensions` is **`2.32 GB` across 17 folders**, of which **`1.27 GB` in 7 folders are dead**:
  * 4 superseded older versions sitting alongside newer versions (`ms-dotnettools.csharp-2.140.9` `318 MB`, `google.geminicodeassist-2.98.0` `237.7 MB`, `anthropic.claude-code-2.1.251` `217.4 MB`, `ms-dotnettools.csdevkit-3.20.199` `174.6 MB`)
  * 3 orphaned `.guid` failed staging folders (`.5e1e46e0...` `147.1 MB`, `.f73ca900...` `92.7 MB`, `.0b447ff5...` `79.1 MB`)
* **Automated Remediation:** Delete `.*` GUID staging folders older than 7 days and superseded lower-semver extension folders in `%USERPROFILE%\.vscode\extensions` when VS Code is closed.

#### 6. Prune Stale Chrome & Edge `Service Worker\CacheStorage` & `Code Cache` (>60 Days Inactive — `708 MB – 2.62 GB`)
* **Disk Space Saved:** **`708 MB – 2.62 GB`**
* **Problem:** Websites that register PWA Service Workers dump offline asset caches into `User Data\Default\Service Worker\CacheStorage\<hash>` and compiled V8 bytecode into `Code Cache` indefinitely (`2.62 GB` across `27,037` files on `BUDSLAPTOP`, with `708 MB` untouched for >60 days).
* **Automated Remediation:** Delete `Service Worker\CacheStorage\<uuid>` folders and `Code Cache` entries whose `LastWriteTime` is older than 60 days across all browser profiles (never touches cookies, saved passwords, active logins, or history).

#### 7. Optimize Common Heavy Collaboration, PDF & Media Apps Across Client PCs (`Microsoft Teams`, `Zoom`, `Adobe Acrobat`, `Slack`, `Discord`, `Spotify`, `Steam`)
* **Disk Space Saved:** **`242 MB`** (`BUDSLAPTOP`) / **`500 MB – 3.5 GB`** (Client PCs) | **RAM Saved:** **`450 MB – 1.5+ GB`** (Client PCs)
* **Problem & Automated Remediations (Dynamically Surfaced When Installed):**
  1. **Microsoft Teams (`MSTeams` New Teams 2.1, `MicrosoftTeams` Consumer Chat, & Dead Classic Teams):**
     * **Auto-Start (`T2.1`):** Disable `MSTeams_8wekyb3d8bbwe\TeamsT2StartupTask\State = 1` for users who only open Teams when joining a meeting (**saves `450–850 MB` of boot RAM**).
     * **Dead Classic Teams Leftovers (`%LOCALAPPDATA%\Microsoft\Teams` & `Teams Machine-Wide Installer`):** Retired in July 2025; auto-check removing orphaned `%LOCALAPPDATA%\Microsoft\Teams` (`600 MB – 2.5 GB`) and `Teams Machine-Wide Installer`.
     * **New Teams `EBWebView` Cache:** Prune >60d `Service Worker\CacheStorage` and `Code Cache` (`300 MB – 1.5 GB`).
  2. **Zoom Workplace (Installed on `BUDSLAPTOP` — `766.8 MB`):**
     * **Hourly Background Updater (`\ZoomUpdateTaskUser-*`):** Currently runs `Zoom.exe --action=UpdateSchedule` **every 1 hour (`Rep=PT1H`)**; reschedule to night-only (`02:10 AM`).
     * **Stale Speech-to-Text Model Cache (`%APPDATA%\Zoom\asr` = `172.3 MB` on `BUDSLAPTOP`, untouched since `11/30/2025`) & Logs:** Prune unused `asr` caches (>90d old) and logs.
  3. **Adobe Acrobat / Reader DC (`~200–350 MB` RAM on Client PCs):**
     * Set `ArmsSvc`, `AGSService`, and `AGMService` to `Manual`, disable `AcroTray` / `AdobeGCInvoker` / `AdobeCollabSync` startup entries, reschedule `\Adobe Acrobat Update Task` to night-only, and set `bAcroSuppressUpsell = 1`.
  4. **Electron / Media Apps (`Slack`, `Discord`, `Spotify`, `Grok Bot`, `Steam`, `Webex`):**
     * Offer 1-click startup disabling (`300–650 MB` RAM saved per app) and prune >30d `Cache\Cache_Data`, `Code Cache` (`70.2 MB` in `%APPDATA%\Grok Bot` on `BUDSLAPTOP`), `GPUCache`, and `Crashpad\reports`.

#### 8. Remove / Disable Unused Xbox, Solitaire & Gaming Subsystem (9 Packages `566.5 MB` + GameDVR + `GameBarPresenceWriter` + Scheduled Task + 4 Services)
* **Disk Space Saved:** **`566.5 MB`** | **RAM Saved:** **`~50–120 MB`** (stops `GameBarPresenceWriter.exe` & `BcastDVRUserService`)
* **Problem:** Windows 11 installs 9 gaming packages (`Microsoft.GamingApp` `309.4 MB`, `Microsoft.MicrosoftSolitaireCollection` `169.4 MB`, `XboxGamingOverlay` `34.3 MB`, `MixedReality.Portal` `18.0 MB`, `XboxIdentityProvider` `17.6 MB`, `Xbox.TCUI` `11.5 MB`, `XboxGameOverlay` `3.0 MB`, `Edge.GameAssist` `2.5 MB`, `XboxSpeechToTextOverlay` `0.8 MB`), enables `GameDVR_Enabled = 1`, and sets `HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter\ActivationType = 1` (spawning `GameBarPresenceWriter.exe` whenever DirectX/OpenGL apps like Trader Workstation, Visual Studio, or Chrome run).
* **Automated Remediation (Single Opt-In Checkbox; `Solitaire` & `MixedReality` Auto-Checked):**
  1. Run `Remove-AppxPackage -AllUsers` and `Remove-AppxProvisionedPackage -Online` for the 9 packages (`566.5 MB`).
  2. Set `GameDVR_Enabled = 0`, `AppCaptureEnabled = 0`, and disable the `GameBarPresenceWriter.exe` WinRT broker (`ActivationType = 0` / IFEO block).
  3. Disable `\Microsoft\XblGameSave\XblGameSaveTask` and set `XblAuthManager`, `XblGameSave`, `XboxGipSvc`, and `XboxNetApiSvc` to `Disabled`.
* **Undo Support:** Restore `GameDVR`, `PresenceWriter`, `\Microsoft\XblGameSave\XblGameSaveTask`, and the 4 Xbox services via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 9. Interactive Brokers Trader Workstation (`C:\Jts\tws.vmoptions`) JVM Tuning + Uninstall Unused `IBKR Desktop` (`C:\ntws` — `488.3 MB`)
* **Disk Space Saved:** **`488.3 MB`** | **Speed/RAM Gain:** Eliminates JVM GC thread contention & UI stalls in TWS
* **Problem:**
  * **Unused `IBKR Desktop` (`C:\ntws` — `488.3 MB`):** Standalone app untouched since **`1/13/2026`** (TWS does not depend on it).
  * **Trader Workstation (`C:\Jts\tws.vmoptions`):** Sets `-XX:ParallelGCThreads=20` on an **8-core / 16-thread Ryzen 7 5700U** (causing GC thread oversubscription), `-XX:MaxGCPauseMillis=200`, and `-Xmx2048m`.
* **Automated Remediation (Opt-In):**
  * Silently uninstall unused **`IBKR Desktop`** (`"C:\ntws\uninstall.exe" -q`, freeing **`488.3 MB`**).
  * Append tuned overrides **below `### keep on update`** in `C:\Jts\tws.vmoptions` (`-Xmx3072m`, `-XX:ParallelGCThreads=8`, `-XX:ConcGCThreads=2`, `-XX:MaxGCPauseMillis=50`, `-XX:+UseStringDeduplication`). *(Never delete the 40-char workspace folders in `C:\Jts`).*
* **Undo Support:** Restore original `tws.vmoptions` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 10. Uninstall `Brother PowerENGAGE` & `Lenovo Now` Bloatware (`444.1 MB`) + Disable Promotional/Unlock Scheduled Tasks
* **Disk Space Saved:** **`444.1 MB`** (`441.5 MB` `Lenovo Now` + `2.6 MB` `PowerENGAGE`) | **Speed Gain:** Stops 6-hour `msiexec /f` repairs & screen-unlock spikes
* **Problem:**
  * **`Brother PowerENGAGE` (`1.0.27`) & `PowerENGAGE` (`3.2.16` by `Aviata, Inc.`) + `\PowerENGAGE` Task:** Runs **every 6 hours**, executing `msiexec /f {400A01BF-E908-4393-BD39-31E386377BDA} /quiet /qn` (Windows Installer force-repair) followed by `PowerENGAGE.exe scheduled-run`.
  * **`Lenovo Now` (`4.8.0.54`, `441.5 MB`) + `\Lenovo\LenovoNow*` Tasks:** Lenovo trialware/adware promoter.
  * **`\GoogleUserPEH\RunPlatformExperienceHelperOnUnlock`** (`_Daily`, `_Metrics`) & **`\SoftLanding\*`**: Fire on every screen unlock and display Office promos.
* **Automated Remediation:** Silently uninstall `Brother PowerENGAGE` (`{3CE8B8E8-B33B-453C-BB7A-821ED6E18A24}` & `{400A01BF-E908-4393-BD39-31E386377BDA}`) and `Lenovo Now` (`"C:\Program Files (x86)\Lenovo\LenovoNow\unins000.exe" /SILENT`), unregister their tasks, and disable `\GoogleUserPEH\*` and `\SoftLanding\*`.

#### 12. Visual Studio & `.NET` Build Speed: Automated Full-Path Defender Exclusions, Night-Only Updates & Cache Cleanup (`178 MB`)
* **Disk Space Saved:** **`178.0 MB`** (`WebView2Cache`) | **Speed/RAM Gain:** 20–40% faster `dotnet build` & lower `MsMpEng.exe` (`380 MB`) CPU/RAM spikes
* **Automated Remediation (Opt-In):**
  * From the elevated Admin Host, run `Add-MpPreference` for `-ExclusionPath` (`%USERPROFILE%\source\repos`, `%USERPROFILE%\.nuget\packages`) and `-ExclusionProcess` using verified full paths (`C:\Program Files\dotnet\dotnet.exe`, `MSBuild.exe`, `VBCSCompiler.exe`, `devenv.exe`).
  * Reschedule `\Microsoft\VisualStudio\Updates\BackgroundDownload` to night-only (`02:30 AM`) and clean `%LOCALAPPDATA%\Microsoft\VisualStudio\WebView2Cache` (`178 MB`).
* **Undo Support:** Run `Remove-MpPreference` and restore task XML via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 13. Clean Stale Office Lock Files and Reset Bloated Excel15.xlb
* **Disk Space Saved:** Remeasure after excluding recovery files. | **Speed Gain:** Addresses stale template locks and oversized Excel toolbar settings.
* **Automated Remediation:** Delete unlocked `~$*.dotm` files in `%APPDATA%\Microsoft\Templates` (`1/13/2026` orphan on `BUDSLAPTOP`); back up and reset `Excel15.xlb` if >1 MB.

---

### Section 2 — Ranked by RAM / Memory Saved (#14 – #24)

#### 14. Shut Down Idle WSL 2 / AI Sandbox Virtual Machine (`vmmem` — `543 MB` WS / `4.10 GB` Committed on `BUDSLAPTOP`) & Set AI VM Services to Manual
* **RAM Saved:** **`543 MB – 1.1 GB` Active WS (`4.10 GB` Committed RAM)**
* **Problem:** `vmmem` keeps a Hyper-V Linux VM allocated in RAM (`4.10 GB` Private Committed RAM on `BUDSLAPTOP`). Claude Desktop (`CoworkVMService`, `Auto`, `25.9 MB`) and OpenAI Codex (`CodexSandboxService.OpenAI.Codex`, `Auto`, `8.4 MB`) boot the VM on every Windows startup.
* **Automated Remediation:** Set `CoworkVMService` and `CodexSandboxService*` to `Manual` and run `wsl.exe --shutdown`.
* **Undo Support:** Restore service `StartMode` to `Automatic` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 15. Expand Startup App Detection to Packaged UWP / Store Startup Tasks (`AppModel\SystemAppData` — `883 MB` Active / `1.22 GB` Committed RAM) *(Phase 2 Detection Implemented ✅)*
* **RAM Saved:** **`232 MB – 883 MB` Active WS (`571 MB – 1.22 GB` Committed RAM)**
* **Problem:** [`WindowsMemorySystem.ReadStartup()`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L271-L312) now scans UWP startup tasks under `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\<Package>\<TaskId>\State` (`2` = Enabled):
  * **`Microsoft.YourPhone` + `MicrosoftWindows.CrossDevice` (`650.5 MB` Active RAM):** Spawns `PhoneExperienceHost.exe` (`389.9 MB`) + `CrossDeviceService.exe` (`156.9 MB`) + `YourPhoneAppProxyHost.exe` (`103.7 MB`). *(Offered and ticked even when a phone is paired: it only stops the automatic start at sign-in, and opening Phone Link starts it as usual.)*
  * **`OpenAI.Codex` (`134.7 MB` Active RAM)**
  * **`AdvancedMicroDevicesInc-2.AMDRadeonSoftware` (`launcherrsxruntimeTask` = `64.3 MB` Active / `353.1 MB` Committed RAM, `151s` CPU):** Disabling stops the Radeon tray/gaming overlay while keeping the core display driver (`amdwddmg.sys`) and hotplug services running.
  * **`E0469640.LenovoUtility` (`33.5 MB` Active / `83.7 MB` Committed RAM)**
  * **`Microsoft.MicrosoftOfficeHub` (`WebViewHostStartupId`)**
* **Automated Remediation:** Set `State = 1` under the UWP StartupTask key via [`WindowsMemorySystem.SetStartupApproved`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L528-L563).
* **Undo Support:** Restore `State = 2` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 16. Disable Windows 11 Taskbar Weather/News Widgets & Start Feed (`WidgetBoard.exe` + `WidgetService.exe` + `MicrosoftStartFeedProvider.exe` + 6 `msedgewebview2.exe` = `~520 MB` RAM)
* **RAM Saved:** **`~520 MB` Active WS**
* **Problem:** Windows 11 Taskbar Widgets (`WidgetBoard.exe` `43.1 MB` + `WidgetService.exe` `14 MB` + `MicrosoftStartFeedProvider.exe` `42.8 MB`) runs **6 hidden `msedgewebview2.exe` processes (`419.5 MB`)**, consuming **`~520 MB` of RAM** on `BUDSLAPTOP` even when never clicked.
* **Automated Remediation:** Set `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa = 0`, remove `Microsoft.StartExperiencesApp`, and terminate `WidgetBoard` / `WidgetService` / `MicrosoftStartFeedProvider`.
* **Undo Support:** Restore `TaskbarDa = 1` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 17. Turn Off Bing Web Search in the Start Menu (`SearchHost.exe` + 6 `msedgewebview2.exe` Processes = `~288–371 MB` RAM)
* **RAM Saved:** **`~288 – 371 MB` Active WS**
* **Why Hiding "Search Highlights" Alone Does NOT Improve Performance:**
  * Setting `IsDynamicSearchBoxEnabled = 0` by itself is **almost purely cosmetic (`~0 MB` RAM saved)** — it hides the daily cartoon icon in the taskbar search box and the "Trending on Bing" cards, but `SearchHost.exe` **still keeps all 6 `msedgewebview2.exe` processes (`~288 MB`) running in RAM** to render live Bing web results when you type.
  * Setting **`HKCU\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions = 1`** is what actually delivers the performance and RAM improvement:
    1. **Reclaims `288–371 MB` of RAM:** Because Start no longer renders web search results, `SearchHost.exe` never spawns the 6 `msedgewebview2.exe` child processes (and `SearchHost.exe` itself drops from `~83 MB` to `~25–35 MB`).
    2. **Instant local Start search:** Typing in the Start menu searches **only local apps, files, and Windows Settings** with zero network round-trip latency to `bing.com` (and also hides the Search Highlights icon/cards automatically).
* **Fix Description Shown to User:**
  * *"Turn off Bing web search results in the Start menu (`288–371 MB` RAM saved). Start menu search will only search local apps, files, and settings instead of querying Bing on the web."*
* **Automated Remediation:** Set `HKCU\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions = 1` (plus `IsDynamicSearchBoxEnabled = 0`) and restart `SearchHost.exe` so the 6 `msedgewebview2.exe` child processes exit immediately.
* **Undo Support:** Restore previous `DisableSearchBoxSuggestions` and `IsDynamicSearchBoxEnabled` values via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs) and restart `SearchHost.exe`.

#### 18. Disable Copilot & Optional Connected Experiences in Office (User-Selected Opt-In — `150–400 MB` RAM)
* **RAM Saved:** **`~150 – 400 MB` Active WS** *(while Office apps are open)*
* **Problem:** Copilot and Optional Connected Experiences spawn hidden `msedgewebview2.exe` child processes inside Word, Excel, and Outlook.
* **Automated Remediation:** Set `HKCU\Software\Microsoft\Office\16.0\Common\Privacy\DisconnectedState = 2` (keeps OneDrive/SharePoint syncing active while disabling optional cloud web panes) and disable Copilot in Word/Excel if selected.
* **Undo Support:** Restore previous registry values.

#### 19. Stop Secondary (Non-Default) Browser from Running in the Background (User-Selected Opt-In — `150–300 MB` RAM)
* **RAM Saved:** **`~150 – 300 MB` Active WS**
* **Problem:** Even when Chrome is the default browser (`ProgId = ChromeHTML`), Microsoft Edge's **Startup Boost** and background mode keep `msedge.exe` processes running in the background (or vice versa).
* **Automated Remediation:** Detect primary browser via `HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice\ProgId` and offer turning off `background_mode.enabled` / `startup_boost_enabled` and `AutoLaunch` `Run` keys for the **secondary browser only**.
* **Undo Support:** Restore previous `Local State` / Registry values.

#### 20. Expand `ServiceCandidates` & Uninstaller Targets for Lenovo `NotifyMe` Telemetry & Brother Background Daemons (`~150 MB` Active / `~394 MB` Committed RAM) *(Service Candidate Detection Implemented; Uninstall Detection Pending)*
* **RAM Saved:** **`~150 MB` Active WS (`~394 MB` Committed RAM)** across 13 background processes
* **Problem:**
  * **`UDCService` (`Universal Device Client Service`, `Auto`) + Child Processes `MessagingPlugin.exe` (`NotifyMe`, `26.9 MB` WS / `60.4 MB` Committed, `73.6s` CPU) & `CoreTelemetryPlugin.exe` (`7.8 MB` WS / `49.8 MB` Committed):** `58.7 MB` Active / `238.5 MB` Committed total.
  * **`LenovoVantage-(GenericMessagingAddin).exe` (`5.6 MB` WS / `37.2 MB` Committed)**.
  * **`LenovoFnAndFunctionKeys` (`LenovoUtilityService` `17.7 MB`) + `FnHotkeyUtility.exe` (`12.0 MB`) + `FnHotkeyCapsLKNumLK.exe` (`3.8 MB`):** `33.5 MB` Active / `83.7 MB` Committed (Opt-In; `IdeaPad 1 15ALC7` `82R4` has no keyboard backlight and `F1–F3` audio / `F5–F6` brightness keys work natively in Windows).
  * **5 Brother Background Processes (`46.4 MB` Active RAM):** `BrYNSvc` (`13.7 MB`), `USBAppControl` (`11.0 MB`), `SoftwareUpdateNotificationService` (`9.6 MB`), `BrLogRx` (`6.2 MB`), `WorkflowAppControl` (`5.9 MB`).
  * **`SQLWriter` (`6.6 MB`, `Auto`)**.
* **Automated Remediation:** Set `UDCService`, `BrYNSvc`, `USBAppControl`, `WorkflowAppControl`, `SQLWriter`, and (when opted in) `LenovoFnAndFunctionKeys` to `Manual` (or `Disabled` for `UDCService`) via [`MemorySuggestionEngine.ServiceCandidates`](../src/RemotePCDiagnostics.Core/Memory/MemorySuggestionEngine.cs#L80-L116), and offer uninstalling `BrLogRx` and `SoftwareUpdateNotification`.
* **Undo Support:** Restore service `StartMode` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 21. Expand Startup App Detection to `HKLM\...\Run`, `WOW6432Node\...\Run`, and Browser `--no-startup-window` Entries (`100–250 MB` RAM) *(Phase 2 Detection Implemented ✅)*
* **RAM Saved:** **`~100 – 250 MB` Active WS**
* **Problem:** [`WindowsMemorySystem.ReadStartup()`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L271-L312) now reads `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` (`hklm32:`, 4 Brother startup items: `BrStsMon00`, `BrotherSoftwareUpdateNotification`, `ControlCenter4`, `I19E`), 64-bit `HKLM\...\Run` (`hklm:`), and `HKCU\...\Run` browser `--no-startup-window` pre-launchers (`GoogleChromeAutoLaunch_*`, `MicrosoftEdgeAutoLaunch_*`, `Microsoft.Lists`, `LenovoVantage`).
* **Automated Remediation:** Disable via `StartupApproved\Run` or `StartupApproved\Run32` in [`WindowsMemorySystem.SetStartupApproved`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L528-L563).
* **Undo Support:** Restore original `StartupApproved` binary value via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 22. Programmatically Block Selected Heavy / Unused Browser Extensions (`ExtensionInstallBlocklist` — `50–150 MB` RAM per Extension)
* **RAM Saved:** **`~50 – 150 MB` Active WS** *(per active extension)* | **Disk Space:** `~46.4 MB`
* **Problem:** On `BUDSLAPTOP`, Chrome has **`PayPal Honey`** (`21.5 MB`) and **`MSN New Tab`** (`1.3 MB`); Edge has **`PayPal Honey`** (`21.7 MB`) and discontinued **`Amazon Assistant`** (`1.9 MB`).
* **Automated Remediation:** Add selected extension IDs to `HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist` or `HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist`.
* **Undo Support:** Remove the extension ID from `ExtensionInstallBlocklist` via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

#### 23. Skip Microsoft Office Start Screen (`DisableBootToOfficeStart`) — Word, Excel & PowerPoint
* **RAM Saved:** **`~15 – 40 MB` Active WS** | **Speed Gain:** **0.5–1.5s faster** Word/Excel/PowerPoint launch
* **Automated Remediation:** Set `DisableBootToOfficeStart = 1` under `HKCU\Software\Microsoft\Office\16.0\Word\Options`, `Excel\Options`, `PowerPoint\Options`, and `Common\General`.
* **Undo Support:** Restore previous registry values.

#### 24. Lock Default Printer to Local (`Microsoft Print to PDF`) on PCs with Network/WSD Printers + Reschedule Office/Zoom Update Tasks to Night-Only (`2:10 AM`)
* **Speed & Responsiveness Gain:** Eliminates **2–10s** Word/Excel launch stalls when network printers sleep, and stops daytime `sdxhelper.exe`, `OfficeC2RClient.exe`, and hourly `Zoom.exe --action=UpdateSchedule` background spikes
* **Automated Remediation:**
  * When both a `WSD-*`/network printer and a local virtual printer (`Microsoft Print to PDF` / fallback `XPS` / `OneNote`) exist, set `LegacyDefaultPrinterMode = 1` and set `Microsoft Print to PDF` as default.
  * Disable `\Microsoft\Office\Office Feature Updates Logon`, `\Microsoft\Office\Office Feature Updates C2R Client Logon`, and `\OneDrive Reporting Task-*`, and reschedule `\Microsoft\Office\Office Feature Updates*` and `\ZoomUpdateTaskUser-*` (`Rep=PT1H`) to once nightly at `02:10 AM`.
* **Undo Support:** Restore previous `LegacyDefaultPrinterMode`, default printer, and scheduled task XML via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).

---

## Part 4: Implementation Roadmap & Status

### ✅ Phase 1 — Pre/Post Benchmarks & Client Report *(Completed & Verified)*
* **[`BenchmarkModels.cs`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs)**: Added `MemoryUsedMb`, `BackgroundProcesses`, `DiskFreeGb`, `EnabledStartupApps`, `AutoVendorServices`, `ActiveScheduledTasks`, and `InstalledBloatwareApps` to [`BenchmarkKind`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs#L8-L12) and [`Benchmarks.All`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs#L29-L46), plus [`BenchmarkDelta.AbsoluteChange`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs#L176) and [`BenchmarkDelta.ChangeSummary`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkModels.cs#L178-L189).
* **[`BenchmarkRunner.cs`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkRunner.cs)** & **[`WindowsBenchmarkProbes.cs`](../src/RemotePCDiagnostics.Host/WindowsBenchmarkProbes.cs)**: Added [`SystemResourceSnapshot`](../src/RemotePCDiagnostics.Core/Benchmarks/BenchmarkRunner.cs#L10-L17) and implemented [`WindowsBenchmarkProbes.ReadResourceSnapshotAsync`](../src/RemotePCDiagnostics.Host/WindowsBenchmarkProbes.cs#L149-L190).
* **[`ClientReport.cs`](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs)**: Updated [`ClientReport.Build`](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs#L51-L63) to display `d.ChangeSummary` (`+41.2 GB freed`, `2000 MB freed (21% less)`, `9 fewer`).

### ⏳ Phase 2 — Hardware, Startup, Service & Storage Detection *(Partially Implemented; Windows Verification Pending)*

The models and several detectors are implemented. Phase 2 is not complete: the current storage scan covers only part of the detailed catalog, and automated Core tests do not verify live Windows registry or filesystem behavior.

| Area | Current coverage | Remaining work |
| :--- | :--- | :--- |
| Browser caches | Chrome and Edge `Default` profiles only | Discover and evaluate all installed browser profiles; test stale-cache eligibility. |
| VS Code extensions | Dot-prefixed staging folders contribute to the estimate | Detect superseded extension versions using version ordering and installed-extension metadata; validate the active version before offering cleanup. |
| NuGet packages | Highest NuGet version and project-assets references under `source/repos` are protected; incomplete scans suppress package candidates | Validate on representative Windows installations; keep projects outside the configured scan root explicitly out of coverage. Deletion is still Phase 3. |
| Worktrees | Grok worktree bytes are still grouped into the auto-checked cache estimate | Split detection and implement item 1a's unchecked selection and separate approval before adding an executor. |
| Hardware, services, startup | Device facts, expanded service candidates, HKCU/HKLM/32-bit Run entries, and UWP startup tasks are implemented | Verify registry reads, permissions, startup changes, and restoration on Windows; service candidates do not imply uninstall detection or executors. |

**Validation evidence:** The latest run passed 610 automated tests and built the Windows Host with zero warnings/errors. Tests cover Core/MemTest behavior, including NuGet selection and failed inventory results; a successful Host build establishes compilation, not live probe or registry round-trip verification. Complete the missing detectors and Windows verification before marking Phase 2 complete.

**Existing startup undo:** `MemorySuggestionService` journals the previous startup value as `ChangeKind.StartupApp`. `UndoService` already restores it through `IMemorySystem.SetStartupApproved`, whose Windows implementation handles HKCU, HKLM, WOW6432Node, and UWP targets. Additional startup undo handlers are not required; live round-trip validation remains pending.

* **[`MemoryModels.cs`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs)**: Added [`StartupScope`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs#L32) (`CurrentUser`, `LocalMachine`, `LocalMachine32`, `PackagedUwp`), [`StartupParsing.UwpAppName`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs#L220-L236), [`StorageCleanupItem`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs#L59), and expanded [`DeviceFacts`](../src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs#L49-L56) (`HasPenDigitizer`, `HasPairedCrossDevice`, `HasNetworkOrWsdPrinter`, `HasLocalPdfPrinter`).
* **[`MemorySuggestionEngine.cs`](../src/RemotePCDiagnostics.Core/Memory/MemorySuggestionEngine.cs)**: Expanded [`ServiceCandidates`](../src/RemotePCDiagnostics.Core/Memory/MemorySuggestionEngine.cs#L80-L116) (`UDCService`, `CoworkVMService`, `BrYNSvc`, `USBAppControl`, `WorkflowAppControl`, `BrLogRx`, `SQLWriter`, `ArmsSvc`, `AGSService`, `AGMService`), [`VendorServiceFragments`](../src/RemotePCDiagnostics.Core/Memory/MemorySuggestionEngine.cs#L119-L132) (`CodexSandboxService`, `SoftwareUpdateNotification`); the startup-app rule (Phone Link is offered and ticked even with a paired phone; vendor tray helpers are listed separately from Electron apps).
* **[`WindowsMemorySystem.cs`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs)**: Expanded [`ReadStartup`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L271-L312) & [`SetStartupApproved`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L528-L563) for `HKLM\...\Run` (`hklm:`), `WOW6432Node` (`hklm32:`), and UWP StartupTasks (`uwp:<Pkg>\<Task>`), plus [`ReadDevices`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L330-L360), [`ReadDefaultBrowser`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L314-L328), and [`ScanStorageCleanups`](../src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs#L362-L460).

### How code folders are found (NuGet pruning #1 and Defender exclusions #12) *(Implemented ✅)*
* [`ProjectLocator`](../src/RemotePCDiagnostics.Core/Projects/ProjectLocator.cs) reads the folders VS Code / Cursor / Windsurf / VSCodium have opened (`workspaceStorage\*\workspace.json`), Visual Studio's recent solutions (`ApplicationPrivateSettings.xml`), Rider's `recentSolutions.xml`, Windows Search hits for `project.assets.json` / `.sln` / `.slnx` / `.csproj`, and common folders (`~\source\repos`, `~\Documents\GitHub`, `X:\src`, `X:\dev`, …). Each hit widens to its `.git` root. Drive roots, the profile and its standard folders, Downloads, Temp, AppData and program folders are never used.
* **NuGet pruning** removes an older version only if: a newer version exists, no found project references it, its `.nupkg.metadata` source is `https://api.nuget.org` (never a company feed or local folder), and it was downloaded more than 45 days ago. A missed project therefore costs a re-download, never a broken build.
* **Defender (#12) is one click:** adds the found code folders (3+ repos in one folder collapse to that folder), `~\.nuget\packages`, and Visual Studio's `devenv.exe`, `MSBuild.exe`, `VBCSCompiler.exe` (not `dotnet.exe`, which runs every .NET app). Only when Defender is the active antivirus and exclusions are readable; read back after adding (organization policy can ignore local exclusions); each exclusion is journaled and undone with `Remove-MpPreference`.

### Undo rules for new fixes
* Every fix declares its [`UndoSupport`](../src/RemotePCDiagnostics.Core/Changes/Undoability.cs): `Full` (previous setting journaled and restored), `NothingToUndo`, `PlaceholdersOnly` (deleted files: undo recreates same-size placeholders for benchmark testing), or `None` (permanent).
* `None` covers `Remove-AppxPackage` / `Remove-AppxProvisionedPackage`, program uninstalls, installed updates, and cache/package deletions. These are journaled as `ChangeKind.NotUndoable`; the workflow shows a **"can't be undone"** chip, and "Undo all" / `--undo-all` lists them as *left as is* instead of failing.
* The storage scan (`ScanStorageCleanupsAsync`) is not part of the memory snapshot; it runs on demand and is cached for 5 minutes.

### ⏳ Phase 3 — Unattended Fix Executors & Undo Support *(Next Step)*
* **Worktree cleanup (item 1a):** Split worktree detection from auto-checked Grok cache cleanup; add an unchecked review item, unchecked per-folder selection, and a separate explicit deletion approval. Preserve the approved paths and findings across restarts, invalidate approval when findings change, and prevent Select all from bypassing approval. Implement linked-worktree and standalone-checkout handling separately, with truthful irreversible-deletion reporting.
* **[`FixCatalog.cs`](../src/RemotePCDiagnostics.Core/Workflow/FixCatalog.cs)** & **[`RemediationService.cs`](../src/RemotePCDiagnostics.Core/Areas/RemediationService.cs)**: Wire the storage cache cleanups (`NuGet` Tier 1+2, `.grok`, VS Code dead commits/VSIXs/extensions, Chrome/Edge >60d `Service Worker` & `Code Cache`), Store/OEM bloatware uninstallers (`Remove-AppxPackage`, `Lenovo Now`, `PowerENGAGE`), registry/scheduled-task optimizations (Taskbar Widgets, Search Highlights, Office Start Screen, Default Printer lock, night-only scheduled tasks), and `wsl --shutdown`.
* **[`UndoService.cs`](../src/RemotePCDiagnostics.Core/Changes/UndoService.cs)**: Reuse the existing `ChangeKind.StartupApp` handler for UWP StartupTask state and HKCU/HKLM/WOW6432Node `StartupApproved`; verify restoration on Windows. Add undo handlers for new registry policy toggles, scheduled task XML restoration, and `powercfg /h` hibernate mode restoration as their executors are implemented.
