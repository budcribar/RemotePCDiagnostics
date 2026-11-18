# Roadmap & Issue Tracker

All unbuilt roadmap items, proposals, and architectural enhancements are tracked as individual GitHub issues in the [**`budcribar/RemoteWebViewAdmin`**](https://github.com/budcribar/RemoteWebViewAdmin/issues) repository. What is already built and operational is documented in [architecture.md](architecture.md) and [module-plugins.md](module-plugins.md).

---

## Contents & Tracked Issues

| Section | Focus Area | Tracked GitHub Issues |
|---|---|---|
| [1. Agent program](#1-agent-program) | Agent service, release workflow, enrollment, reboot continuity | [#52](https://github.com/budcribar/RemoteWebViewAdmin/issues/52), [#53](https://github.com/budcribar/RemoteWebViewAdmin/issues/53), [#54](https://github.com/budcribar/RemoteWebViewAdmin/issues/54) |
| [2. Host queries for third-party modules](#2-host-queries-for-third-party-modules) | Unprivileged module sandboxing, redacted event logs, allowlists | [#55](https://github.com/budcribar/RemoteWebViewAdmin/issues/55), [#56](https://github.com/budcribar/RemoteWebViewAdmin/issues/56), [#57](https://github.com/budcribar/RemoteWebViewAdmin/issues/57), [#58](https://github.com/budcribar/RemoteWebViewAdmin/issues/58), [#59](https://github.com/budcribar/RemoteWebViewAdmin/issues/59), [#60](https://github.com/budcribar/RemoteWebViewAdmin/issues/60) |
| [3. Service workflow fixes still to build](#3-service-workflow-fixes-still-to-build) | Visual Studio build speed, worktree cleanup | [#69](https://github.com/budcribar/RemoteWebViewAdmin/issues/69), [#70](https://github.com/budcribar/RemoteWebViewAdmin/issues/70) |
| [4. Remote trust model](#4-remote-trust-model) | Scoped permissions and remote user control ceilings | [#53](https://github.com/budcribar/RemoteWebViewAdmin/issues/53) |
| [5. Proposals](#5-proposals) | Application optimization modules and hardware diagnostics | [#61](https://github.com/budcribar/RemoteWebViewAdmin/issues/61)–[#68](https://github.com/budcribar/RemoteWebViewAdmin/issues/68), [#71](https://github.com/budcribar/RemoteWebViewAdmin/issues/71)–[#75](https://github.com/budcribar/RemoteWebViewAdmin/issues/75) |
| [6. Out-of-process review: open suggestions](#6-out-of-process-review-open-suggestions) | Action forwarding in `ModuleUiHost`, PID polling elimination | [#76](https://github.com/budcribar/RemoteWebViewAdmin/issues/76), [#77](https://github.com/budcribar/RemoteWebViewAdmin/issues/77) |
| [7. AI connector data leaving the PC](#7-ai-connector-data-leaving-the-pc) | PII sanitization and user profile path redaction | [#78](https://github.com/budcribar/RemoteWebViewAdmin/issues/78) |

---

## 1. Agent program

The background agent runs as a Windows service on client endpoints, connecting outbound to the relay on Railway so remote technicians can initiate diagnostics without manual client pre-installations.

- **Completed Foundation:** Relay gRPC services (`AgentHub` / `AgentAdmin`), admin **Computers** page in RemoteWebViewAdmin, agent protocol contract (`agent.proto`), and pure logic library (`RemotePCDiagnostics.Agent.Core`).
- **Open Work Items:**
  - **[#52](https://github.com/budcribar/RemoteWebViewAdmin/issues/52) — Release workflow, manifest signing key & automated release publishing:** Implement `tools/New-ManifestSigningKey.ps1` and `.github/workflows/release.yml` with ECDSA P-256 signature verification so the agent can verify downloaded app bundles.
  - **[#53](https://github.com/budcribar/RemoteWebViewAdmin/issues/53) — Per-install credentials, enrollment key scoping, and self-update:** Replace shared enrollment keys with per-endpoint credentials and automated agent binary self-updates.
  - **[#54](https://github.com/budcribar/RemoteWebViewAdmin/issues/54) — Session reboot continuity & post-restart relaunch:** The agent service automatically relaunches the Host after a scheduled reboot during mid-workflow testing, and handles agent-driven `--undo-all`.

---

## 2. Host queries for third-party modules

Enables unprivileged third-party modules running in user mode (`ModuleHost.exe`) to query necessary elevated hardware metrics without granting the module administrator rights.

- **Open Work Items:**
  - **[#55](https://github.com/budcribar/RemoteWebViewAdmin/issues/55) — Deny INTERACTIVE token group for out-of-process modules:** Add `S-1-5-4` (`INTERACTIVE`) and `Event Log Readers` to deny-only SIDs in `RestrictedModuleHostLauncher` to prevent unredacted event log reads.
  - **[#56](https://github.com/budcribar/RemoteWebViewAdmin/issues/56) — Module process isolation (AppContainer or Windows Firewall rules):** Sandbox `ModuleHost.exe` and `ModuleUiHost.exe` to block network exfiltration and access to personal files.
  - **[#57](https://github.com/budcribar/RemoteWebViewAdmin/issues/57) — Replace JSON check denylist with strict osquery table allowlist:** Enforce an allowlist of safe read-only hardware/OS tables for `osquery.select`, blocking `file`, `hash`, `yara`, `registry`, and `shell_history`.
  - **[#58](https://github.com/budcribar/RemoteWebViewAdmin/issues/58) — Redacted Event Log API (`eventlog.read`):** Provide structured event log access with stable pseudonymized placeholders (`<user:xxxx>`, `<path:xxxx>`) and keep-lists for system error codes.
  - **[#59](https://github.com/budcribar/RemoteWebViewAdmin/issues/59) — Opaque per-device instance keys:** Generate `HMAC-SHA256(installSecret, moduleId + rawId)` keys so modules can track hardware history without exposing serial numbers.
  - **[#60](https://github.com/budcribar/RemoteWebViewAdmin/issues/60) — App-owned fix requests for user-mode modules:** Allow user-mode modules to propose validated app remediations (`AreaAction`) with standard confirmation, change journaling, undo support, and actor attribution.

---

## 3. Service workflow fixes still to build

Operational cleanups and performance fixes for system optimization workflows.

- **Open Work Items:**
  - **[#69](https://github.com/budcribar/RemoteWebViewAdmin/issues/69) — Visual Studio & .NET build speed optimization:** Automated Defender exclusions (`Add-MpPreference`) for repo folders, NuGet cache, and compiler binaries, with night-only VS background update scheduling.
  - **[#70](https://github.com/budcribar/RemoteWebViewAdmin/issues/70) — Review and cleanup of unused agent worktrees and checkouts:** Identify stale `.grok/worktrees` and `.claude/worktrees`, inspect Git tracking state, and require explicit separate approval before deletion.

---

## 4. Remote trust model

- **Overview:** Defines boundaries and permission tiers for remote sessions. Currently, any remote user granted control has identical administrative power to the local user.
- **Tracked Under:** [#53](https://github.com/budcribar/RemoteWebViewAdmin/issues/53) (Credential scoping, per-computer permission limits, and consent ceilings).

---

## 5. Proposals

Diagnostic modules and hardware integrity tests to identify software bottlenecks and peripheral faults.

### Application Optimization Modules
- **[#61](https://github.com/budcribar/RemoteWebViewAdmin/issues/61) — Module 1: Top resource consumers report (process-tree rollup):** Walk parent PIDs to group Chrome, Edge, WebView2, and Electron helper processes under their parent applications.
- **[#62](https://github.com/budcribar/RemoteWebViewAdmin/issues/62) — Module 2: Startup items list with impact & OEM bloatware analyzer:** Enumerate Run/RunOnce keys, Startup folders, and scheduled tasks; flag OEM bloatware and provide reversible disable actions via `StartupApproved`.
- **[#63](https://github.com/budcribar/RemoteWebViewAdmin/issues/63) — Module 3: Antivirus conflicts & cloud sync activity check:** Detect dual active real-time AV engines, running Defender scans, and stuck OneDrive/Dropbox sync states consuming sustained CPU/disk.
- **[#64](https://github.com/budcribar/RemoteWebViewAdmin/issues/64) — Module 4: Browser check (memory, extensions, and hardware acceleration):** Roll up process counts/memory for Chrome, Edge, Firefox; inventory extensions and check hardware acceleration.
- **[#65](https://github.com/budcribar/RemoteWebViewAdmin/issues/65) — Module 5: Office & email add-in check (data file sizes & slow add-ins):** Measure OST/PST data file sizes, read COM add-in startup times, and flag heavy Exchange caching options.
- **[#66](https://github.com/budcribar/RemoteWebViewAdmin/issues/66) — Module 6: Communication & meeting apps load check:** Monitor Teams, Zoom, Slack, Discord memory footprint and call-time CPU/GPU encoding.
- **[#67](https://github.com/budcribar/RemoteWebViewAdmin/issues/67) — Module 7: Media apps hardware acceleration check:** Verify Spotify, VLC, and browser streaming processes utilize GPU hardware decoding.
- **[#68](https://github.com/budcribar/RemoteWebViewAdmin/issues/68) — Module 8: Developer tools resource monitor (WSL2, Docker, VS):** Monitor memory allocated to WSL2 (`vmmem`) and Docker Desktop, providing explicit `wsl --shutdown` remediation.

### Hardware & Peripheral Diagnostics
- **[#71](https://github.com/budcribar/RemoteWebViewAdmin/issues/71) — Hardware: Video-memory integrity test (offscreen D3D buffer pattern verification):** Allocate bounded GPU memory, write test patterns, and detect bit errors or device resets without requiring screen observation.
- **[#72](https://github.com/budcribar/RemoteWebViewAdmin/issues/72) — Hardware: Headless display checks & driver crash correlation:** Inspect active resolution, refresh rate, HDR state, scaling, and correlate mode changes with recorded GPU resets.
- **[#73](https://github.com/budcribar/RemoteWebViewAdmin/issues/73) — Hardware: Guided keyboard, touchpad, and touchscreen diagnostic:** Interactive visual test for key presses, multi-touch gestures, and digitizer coverage.
- **[#74](https://github.com/budcribar/RemoteWebViewAdmin/issues/74) — Hardware: Standby sleep, wake, and resume diagnostic:** Query last wake source, sleep blockers (`powercfg -requests`), and abnormal modern standby battery drain.
- **[#75](https://github.com/budcribar/RemoteWebViewAdmin/issues/75) — Hardware: Dock and USB-C connection health monitor:** Monitor multi-function dock stability, network/display drops, and simultaneous peripheral disconnects.

---

## 6. Out-of-process review: open suggestions

Follow-ups from the out-of-process architecture review of `ModuleHost` and `RemoteBlazorWebView.RemoteComponents`.

- **[#76](https://github.com/budcribar/RemoteWebViewAdmin/issues/76) — Out-of-Process: ModuleUiHost AreaAction callback forwarding:** Forward user-mode module UI actions back to the host via contract callbacks without stripping `AreaAction` from bundled modules.
- **[#77](https://github.com/budcribar/RemoteWebViewAdmin/issues/77) — Out-of-Process: Eliminate PID polling in RemoteComponentHost.ExitWithParent:** Replace `Process.GetProcesses()` polling loop with anonymous stdin pipe EOF detection (`connection.Closed`) for zero-overhead exit detection.

---

## 7. AI connector data leaving the PC

- **[#78](https://github.com/budcribar/RemoteWebViewAdmin/issues/78) — AI Connector: Personal data & user profile path redaction:** Scrub user account names, machine hostnames, and personal profile paths (`C:\Users\<username>\...` → `%USERPROFILE%`) from `area-report-data` and diagnostic MCP tool results before external customer use.
