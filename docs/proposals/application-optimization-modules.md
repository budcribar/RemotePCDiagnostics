# Proposal: Application optimization modules

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-11-02 |
| **Author** | Bud Cribar (drafted via assistant) |
| **Scope** | New on-demand diagnostic modules for RemotePCDiagnostics |

## Summary

RemotePCDiagnostics already tells a technician whether the *hardware* is healthy: osquery inventory, LibreHardwareMonitor sensors, CPU/disk/memory/network/GPU stress tests, a security audit, and speaker/microphone audio tests, with webcam and NPU tests in progress. Many "my laptop is slow" complaints, however, are caused by *software*: a browser with dozens of tabs and extensions, a cloud sync client stuck re-indexing, two antivirus products fighting, OEM utilities at startup, or WSL holding gigabytes of memory.

This proposal adds a set of **application optimization modules** that identify which applications are consuming resources on a typical Windows laptop, explain why it matters, and point the technician at a fix. Detection is read-only. Fixes are always a separate, explicit technician action. The work is split into three phases, starting with three general-purpose modules that cover most cases.

Statements in this document about how much resource a given application typically uses are **general observations**, not measurements. No figures here come from profiling; any thresholds must be established and validated during implementation.

## Goals

- Name the application (not just the process) responsible for high CPU, memory, or disk use.
- Show what starts with Windows and estimate its impact, flagging OEM bloatware.
- Detect background activity that commonly makes a machine feel slow: antivirus scans, cloud sync problems, indexing, updates.
- Give app-specific guidance for the most common heavy applications (browsers, Office/Outlook).
- Work on typical Windows laptops from any vendor, not only the Lenovo IdeaPad 1 15ALC7 (Ryzen 7 5700U) used for development.
- Work identically in local and remote (RemoteBlazorWebView) mode.

## Non-goals

- Automatic remediation. No module changes system state during a scan.
- Replacing the security audit. Antivirus *health* stays in the security audit; this proposal only looks at antivirus *performance impact*.
- Uninstalling software, editing user content, or changing app settings without a technician action.
- Telemetry, cloud lookups, or uploading any collected data.
- Restyling the existing UI.

## Design principles

1. **No confirmation prompts before tests.** Technicians already have admin rights; modules run when selected.
2. **Read-only by default.** Every module produces findings only. Any fix (disable a startup item, disable an add-in, restart a sync client) is a separate button the technician presses deliberately, with the exact change shown, and is logged in the report.
3. **Security audit stays separate.** It is not part of the stress run, and these modules do not merge into it.
4. **On-demand and unticked by default.** New modules appear in the module list *after* the security audit and are not selected by default, so the existing stress run is unchanged.
5. **No UI restyling.** New modules reuse existing result components and layout.
6. **Privacy and minimal collection.** Collect process names, publishers, counts, and sizes, not document titles, URLs, browsing history, email content, or file names inside user folders. Nothing is uploaded. In remote mode, only the summarized findings are shown to the technician.
7. **Core logic behind interfaces; Windows-only code in the host.** As with the audio tests: classification and verdict rules live in `RemotePCDiagnostics.Core` behind interfaces (e.g. `IProcessSnapshotSource`, `IStartupItemSource`), with Windows data collection (WMI, performance counters, registry, osquery) in `RemotePCDiagnostics.Host`.
8. **Unit tests on synthetic data.** Rules are tested in `RemotePCDiagnostics.Tests` against synthetic snapshots (fake process trees, startup lists, sync states). CI (`.github/workflows/ci.yml`) is the build check; no tests require a live Windows session.
9. **Rules as data.** Known apps, publishers, and thresholds are kept in a data file (similar in spirit to `docs/sensor-thresholds.md`) so lists can grow without code changes.

## Priority roadmap

| # | Module | Phase | Priority | Depends on | Notes |
|---|---|---|---|---|---|
| 1 | Top resource consumers report | 1 | High | osquery, perf counters | Foundation for most later modules |
| 2 | Startup items with impact | 1 | High | osquery, registry | Includes OEM bloatware flags |
| 3 | Antivirus and cloud sync activity | 1 | High | #1, WMI/Defender | AV health remains in security audit |
| 4 | Browser check | 2 | Medium | #1, osquery browser tables | |
| 5 | Office and email add-in check | 2 | Medium | registry, file sizes | Relates to existing `OutlookBenchmark` |
| 6 | Communication and meeting apps | 3 | Low | #1, webcam/audio tests | |
| 7 | Media apps | 3 | Low | #1, GPU sensors | |
| 8 | Developer tools | 3 | Low | #1 | WSL2/vmmem, Docker |
| 9 | Gaming launchers and overlays | 3 | Low | #1, #2 | |
| 10 | Manufacturer tools and bloatware | 3 | Low | #2 | Likely folded into #2 |
| 11 | Background system activity | 3 | Low | #1, #3 | Likely folded into #1/#3 |

Several Phase 3 items overlap with modules 1 and 2. Where that happens, they should be implemented as **rule sets** (data) consumed by modules 1–3 rather than separate modules.

## Common output format

Each module returns the same shape as existing modules:

- **Verdict:** `Pass`, `Warning`, or `Fail`.
- **Findings:** a list of items, each with
  - `Severity` (Info / Warning / Fail)
  - `Application` (friendly name and publisher)
  - `Observation` (what was seen, e.g. "17 processes, rolled up to Google Chrome")
  - `Why it matters` (one sentence)
  - `Suggested action` (text; optional link to an explicit fix action)
  - `Evidence` (minimal raw values: process count, working set, CPU %, file size)
- **Collection notes:** what could not be read (e.g. per-user data for another user, access denied), so a missing finding is not mistaken for a clean result.

Verdict rule of thumb: `Fail` only for clear, actionable problems (e.g. two real-time AV products active); `Warning` for likely contributors; `Pass` otherwise.

---

## Phase 1

### 1. Top resource consumers report

**What it checks.** Samples CPU, memory (working set and private bytes), and disk I/O per process over a short window, groups processes into applications using the process tree and executable path, and reports the top applications by each resource.

**Why it matters.** Task Manager shows dozens of `chrome.exe`, `msedgewebview2.exe`, or Electron helper processes separately; the user and technician need "Chrome is using most of the memory", not 30 lines. This is also the data foundation for modules 3–11.

**Implementation notes.**
- osquery `processes` (pid, parent, path, resident size, user/system time) for the snapshot; two samples a few seconds apart give CPU deltas.
- Windows Performance Counters (`Process` category: `% Processor Time`, `Working Set - Private`, `IO Read/Write Bytes/sec`) as an alternative or cross-check. *Hypothesis to verify:* whether perf counters or osquery deltas are more reliable on low-core laptops without disturbing the result.
- Grouping: walk parent PIDs up to the top-level app process; fall back to grouping by executable path and file version `ProductName`/`CompanyName`. WebView2 hosts (`msedgewebview2.exe`) should be attributed to their parent app where possible. *Hypothesis:* parent-PID chains are sometimes broken when parents exit; path-based grouping is the fallback.
- Report system totals (commit charge vs installed RAM, pagefile use) so per-app numbers have context.
- Do not collect command lines or window titles by default (they can contain URLs and file names).
- Testability: `IProcessSnapshotSource` returning synthetic trees; tests cover rollup, orphaned children, and ranking.

### 2. Startup items list with impact

**What it checks.** Enumerates everything that starts at sign-in or boot, whether it is enabled, its publisher, and an estimated impact; flags known OEM bloatware and unsigned or unknown entries.

**Why it matters.** Startup load is a common cause of slow boot and sluggish first minutes after sign-in, especially on laptops with modest RAM and pre-installed OEM software.

**Implementation notes.**
- Sources: registry Run/RunOnce keys (HKLM and HKCU, including `WOW6432Node`), user and common Startup folders, `Win32_StartupCommand` (WMI), osquery `startup_items`, `scheduled_tasks` (logon/boot triggers), and `services` (auto-start, non-Microsoft).
- Enabled state: `HKCU/HKLM\...\Explorer\StartupApproved\Run` and `StartupFolder` values, which reflect Task Manager's enable/disable toggles.
- Impact: use Windows' own startup impact data where available. *Hypothesis to verify:* Task Manager's "Startup impact" is derived from boot diagnostics data that may not be exposed through a stable API; if not readable, estimate impact from binary publisher, process size at runtime (module 1), and whether it stays running.
- Publisher from Authenticode signature and file version info; classify Microsoft / OEM / third-party / unsigned.
- OEM bloatware: a data list (Lenovo, HP, Dell, ASUS, Acer, MSI utilities, trialware) with "keep / review / optional" guidance; some vendor utilities provide firmware and driver updates and should not be blindly flagged.
- Fix action (separate, explicit): disable via `StartupApproved` the same way Task Manager does, so it is reversible.
- Target list and safety ratings: see [Startup cleanup targets](startup-cleanup-targets.md).

### 3. Antivirus and cloud sync activity check

**What it checks.** Whether antivirus or cloud sync is actively consuming resources *right now*, and whether either is in a bad state.

- Antivirus: real-time protection active, a quick/full scan running, AV process CPU/disk use, and more than one real-time AV product registered.
- Cloud sync: OneDrive, Dropbox, Google Drive, iCloud running; signs of stuck sync, re-indexing, or error state; high sustained CPU/disk.

**Why it matters.** A scheduled full scan or a sync client re-indexing a large folder can saturate disk and CPU on a laptop and is easy to mistake for a hardware fault, which can also skew stress-test results. Two real-time AV products often conflict.

**Implementation notes.**
- Defender: `Get-MpComputerStatus` (or `MSFT_MpComputerStatus` in `root\Microsoft\Windows\Defender`) for real-time state, last scan times, and scan in progress. *Hypothesis to verify:* which field reliably indicates a scan *currently* running versus last scan.
- Third-party AV: `root\SecurityCenter2` `AntiVirusProduct` (workstation only; not present on Server); decode `productState` for enabled/up-to-date. Report two enabled products as `Fail`.
- AV process load from module 1 (e.g. `MsMpEng.exe`, vendor engines).
- OneDrive: process presence and load; per-user registry under `HKCU\Software\Microsoft\OneDrive\Accounts`; sync state. *Hypothesis:* sync status is not exposed via a public API; logs under `%LOCALAPPDATA%\Microsoft\OneDrive\logs` are binary/obfuscated, so detection may be limited to process load over time plus account configuration.
- Dropbox / Google Drive / iCloud: process presence and sustained load; vendor status files where documented. Treat state detection beyond "sustained high load" as a hypothesis.
- This module reports performance impact only. AV configuration and health remain in the security audit.

## Phase 2

### 4. Browser check

**What it checks.** For Chrome, Edge, and Firefox: process count, total memory (rolled up from module 1), number of installed extensions, hardware acceleration setting, and flags for extensions known to be heavy or suspicious.

**Why it matters.** Browsers are commonly the largest memory consumer on a laptop. Extensions run on every page, and disabled hardware acceleration shifts video decode to the CPU.

**Implementation notes.**
- osquery `chrome_extensions` (covers Chromium-based browsers including Edge, per profile), `firefox_addons`, `browser_plugins`.
- Hardware acceleration: Chromium `Local State` (`hardware_acceleration_mode`) and Firefox `prefs.js`. *Hypothesis:* key names and defaults vary by version; verify on current builds.
- Extensions are reported by name and ID only. No history, bookmarks, URLs, or tab titles.
- Heavy-extension list maintained as data; start small and conservative.
- Policy-managed settings (`HKLM\Software\Policies\...`) noted, since the technician may not be able to change them.

### 5. Office and email add-in check

**What it checks.** Outlook data file sizes (OST/PST), COM add-ins for Outlook/Word/Excel with load behavior and load time, and Outlook options that commonly slow startup.

**Why it matters.** Large OST files, slow add-ins, and caching shared mailboxes are common causes of slow Outlook startup. The repo already contains `src/OutlookBenchmark`; this module should reuse or align with it.

**Implementation notes.**
- COM add-ins: `HKCU`/`HKLM\Software\Microsoft\Office\<App>\Addins\*` (`LoadBehavior`, `FriendlyName`), plus `WOW6432Node`. Disabled-item and slow-add-in data under `...\Office\16.0\<App>\Resiliency`. *Hypothesis:* Office records add-in load times in Resiliency keys; format to verify.
- OST/PST size: file sizes in `%LOCALAPPDATA%\Microsoft\Outlook` (size only, never content).
- Cached Exchange settings from the Outlook profile registry. *Hypothesis:* "Download shared folders" and "Download headers only" flags are readable from the profile; verify, otherwise report as guidance only.
- Reference tips (from Bud) to surface as guidance where detection supports them:
  - Outlook › File › Options › Advanced: turn off **Download shared folders** on cached Exchange accounts if not needed.
  - Outlook: turn off **Download headers only** on the cached Exchange account.
  - Disable unneeded COM add-ins in Outlook, Word, and Excel.
  - Word: turn off **Open e-mail attachments in Full Screen Reading view** if not needed.
- Fix action (explicit): set `LoadBehavior` to disable a selected add-in, reversible.

## Phase 3 (lower priority)

### 6. Communication and meeting apps

**Checks.** Teams, Zoom, Slack, Discord: running state, rolled-up memory, and CPU/GPU during a call.
**Why.** These are often Electron/WebView2 apps that stay resident; call-time video encoding is CPU/GPU heavy on entry-level laptops.
**Notes.** Mostly rules on module 1 data. Optional "call load" sample while the technician runs a test call; link findings to the webcam and audio tests so device and app problems are separated.

### 7. Media apps

**Checks.** Spotify, VLC, browser streaming: whether video decode is hardware-accelerated.
**Why.** Software decode raises CPU use, heat, and battery drain.
**Notes.** GPU engine counters (`GPU Engine` category, `engtype_VideoDecode`) per process. *Hypothesis:* per-process video decode counters are reliable on AMD/Intel integrated GPUs; verify.

### 8. Developer tools

**Checks.** Visual Studio, VS Code, Docker Desktop, WSL2 (`vmmem`/`vmmemWSL`), Node, Android emulators; memory held after use.
**Why.** WSL2 and emulators can hold large amounts of memory after work is finished.
**Notes.** `wsl --status` / `wsl --list --verbose` for running distros; `vmmem` working set from module 1; `.wslconfig` memory limit presence. Fix action (explicit): `wsl --shutdown`.

### 9. Gaming launchers and overlays

**Checks.** Steam, Epic, Xbox Game Bar, Discord and GeForce/Radeon overlays, RGB/peripheral software.
**Why.** Launchers and overlays often start with Windows and hook into rendering.
**Notes.** Mostly startup rules (module 2) plus Game Bar/Game DVR registry settings.

### 10. Manufacturer tools and bloatware

**Checks.** Lenovo Vantage, HP Support Assistant, Dell SupportAssist, ASUS/Acer/MSI utilities, trialware.
**Why.** Common on new laptops; some are useful (firmware/driver updates), some are not.
**Notes.** Best implemented as the OEM rule list inside module 2, with osquery `programs` for installed software.

### 11. Background system activity

**Checks.** Windows Search indexing, Windows Update downloads/installs, Delivery Optimization, maintenance tasks, `TiWorker`/`SearchIndexer` load.
**Why.** Temporary but heavy; a technician should know to wait rather than diagnose hardware.
**Notes.** Rules on module 1 plus service state. Likely folded into module 3 as a general "busy in background" finding.

---

## Risks

- **False positives.** Flagging a needed OEM utility or a legitimate extension erodes trust. Mitigation: conservative rule lists, "review" rather than "remove" wording, `Warning` not `Fail` unless clear.
- **Point-in-time sampling.** A short sample can miss or exaggerate intermittent load. Mitigation: report sample duration; allow a longer sample on request.
- **Remote-mode privacy.** Remote technicians see findings from the user's machine. Mitigation: no command lines, URLs, titles, or file names; summarized output only; nothing uploaded.
- **Per-user vs per-machine data.** HKCU, browser profiles, OneDrive, and Outlook data belong to the signed-in user; the host may run elevated or as a different account. Mitigation: resolve the interactive user's hive/profile explicitly and record what could not be read in collection notes.
- **Undocumented sources.** Startup impact, sync state, and some Office settings may rely on undocumented data that changes between versions. Mitigation: mark as best-effort and degrade to "not available".
- **Fix actions.** Any change must be explicit, reversible where possible, and logged.

## Open questions for Bud

1. Should module output appear only in the on-screen results, or also in the saved client report?
2. Should fix actions ship in the first release, or detection only at first?
3. Is a separate list of "approved" OEM utilities per vendor wanted (e.g. keep Lenovo Vantage for firmware updates)?
4. How long a sampling window is acceptable for module 1 (seconds vs a minute)?
5. Should `OutlookBenchmark` and `NetworkUsagePrototype` be merged into these modules or stay standalone?
6. Is there a target set of test laptops beyond the IdeaPad 1 15ALC7 for validating rules?

## Rough sequencing

1. Shared contracts in Core: process snapshot, app grouping, finding/verdict types; synthetic-data tests.
2. Module 1 (top consumers) end to end, wired into the module list after the security audit, unticked by default.
3. Module 2 (startup items) including OEM rule list; then its explicit disable action.
4. Module 3 (AV and cloud sync), reusing module 1 data.
5. Phase 2: browser check, then Office/email add-in check (aligned with `OutlookBenchmark`).
6. Phase 3 items as rule sets on modules 1–3, promoting any to a standalone module only if it needs its own data collection (e.g. call-time sampling, WSL).
7. After each step: CI build green, unit tests on synthetic data, manual verification on at least one non-Lenovo laptop.
