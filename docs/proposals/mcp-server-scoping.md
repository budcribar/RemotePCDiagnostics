# MCP server scoping: an AI technician

Proposal only. This document does not change the app, the agent, or the relay.

The diagnostics app and the enrollment agent become an MCP server. An AI model talks to the person at the PC, calls the tools below, walks them through the interactive tests that already exist, and helps debug the machine. The model is the technician. The app remains the thing that touches Windows.

The work is three phases. Phase 1 is read-only tools a local MCP client (Cursor or Claude Desktop) can call. Phase 2 adds guided interactive tests, and only while `ISessionContext.Mode` is `SessionMode.Local`. Phase 3 adds a chat panel in the current Blazor UI and lets the admin site start an AI session for a shop whose subscription allows it.

Names below are the types and files in this repo today, plus the relay behavior documented in `budcribar/RemoteBlazorWebView`. Proposed tool names (`get_inventory`, and the rest) are new. They are not methods yet.

## Where this sits in the current app

| Piece | What it is today |
| --- | --- |
| `src/RemotePCDiagnostics.Agent` | Windows service `RemotePCDiagnosticsAgent` (`AgentLayout.ServiceName`). `AgentHubWorker` holds the outbound `AgentHub.Connect` stream. `AgentCommand` is `Help`, `Install`, `Uninstall`, `Status`, `Run`, `Consent`, `Launch`, `Helper`. |
| `src/RemotePCDiagnostics.Agent/Protos/agent.proto` | Contract shared with `budcribar/RemoteBlazorWebView` and `budcribar/RemoteWebViewAdmin`. The hub sends `LaunchCommand` and `CancelCommand`. The admin site calls `AgentAdmin.StartSession`, which returns `app_url` (`<server>/mirror/<session_id>`). |
| `AgentPaths` / `AgentLayout` | `%ProgramData%\RemotePCDiagnostics\agent.json` holds the enrollment key (`AgentConfig.Key`). `agent-status.json` (`AgentLinkStatus`, written by `AgentStatusPublisher`) has `connected`, `updatedUtc`, and `group`, and never the key. `active-session.json` is `ActiveSessionInfo`. |
| `src/RemotePCDiagnostics.Host` | Elevated WPF app. `HostServices` is the composition root: `DiagnosticsService`, `ResultStore`, `OsqueryRunner`, `LhmSensorProvider`, the module catalog. `[RemoteBlazor]` on `MainWindow` calls `InitializeRemoteBlazor()`. |
| `ISessionContext` | `SessionMode.Local` or `SessionMode.Remote`, plus `ServerUri`, `SessionId`, `Unattended`, `Voice`, `Group`, `Admin`. `SessionLaunchOptions.DefaultServerUrl` is `https://remoteblazorwebview.com:34544`. The agent's default is `AgentCommandLine.DefaultServer`, `https://server.remoteblazorwebview.com:34544`. |
| UI | `src/RemotePCDiagnostics.UI`. `Shared/MainLayout.razor` is the top bar. `Shared/NavRail.razor` is Dashboard, Service workflow, Checks, Stress tests, Interactive tests, Security audit, Benchmark, QA & branding, History, About. |
| Read-only checks | `/checks` is `CheckGroup.Checks`. `DiagnosticsService.RunAsync` runs one module. `ResultStore.Get` returns the latest `DiagnosticResult`. |
| Stress | `/stress` is `CheckGroup.Stress`. `CpuStressModule`, `MemoryTestModule`, `DiskSpeedModule`, `GpuStressModule`, and `NetworkTestModule` implement `IStressSuiteModule`. Each comment says the test never auto-runs and is excluded from Run All. `DiagnosticsService.RunStressSuiteAsync` takes `StressSuiteMode.Short` (1 minute each, `StressSuiteDurations`) or `StressSuiteMode.Extended` (5 minutes). |
| Interactive | `/interactive` is `InteractiveTestsPage.razor`: `PhysicalBenchQaCard` over `PhysicalBenchQaService`, `WebcamTestModule`, `MicToSpeakerModule`, `SpeakerToMicModule`. |
| Undo | `IChangeJournal` / `FileChangeJournal` at `ProtectedState.ChangesFile` (`%ProgramData%\RemotePCDiagnostics\state\changes.json`). `UndoService.UndoAllAsync` reverts `ChangeRecord`s. `ServiceActor` is `"Local user"` or `"Remote user"`. |
| Shop billing signal in this repo | `ShopRelayClient` calls `GET {shop}/api/shops/{group}/branding` and `POST {shop}/api/reports` with `Bearer rpd_live_...`. Inactive shops come back as `ShopRelayBrandingResult.NotFoundOrInactive` or HTTP 402 `ShopReportPublishResult.PaymentRequired`. `ShopRelayClient.DefaultShopPortalUrl` is `https://admin.remoteblazorwebview.com`. |
| Existing AI handoff | `ICopilotHandoff` / `CopilotHandoff` opens a WebView2 window on `https://copilot.microsoft.com/` and pastes a prompt. `HostServices` registers it only when `SessionMode` is `Local`. |

`docs/architecture.md` still says the agent program is not built. `RemotePCDiagnostics.Agent` and `AgentHubWorker` are built. This proposal follows the code.

### Remote read-only vs local interactive

`AgentMode.Tooltip` is the sentence already shown on the badge: "Remote: read-only checks. Local: interactive tests."

`MainLayout.razor` draws that badge only in a remote session. `AgentModeMonitor` polls `AgentModeReader`, which reads `agent-status.json` (fresh for `AgentMode.LinkFreshness`, 90 seconds) and the agent install. `AgentModeSnapshot.Label` is "Agent connected · {group}", "Agent connected", "Agent installed, not connected", or "Local only". `CssClass` reuses `badge badge-remote`, `badge`, and `badge badge-local`. The snapshot comment says to keep the existing badge classes. A local session shows a plain "Local" badge and does not show `AgentModeSnapshot`.

`InteractiveTestsPage` still renders the tests during `SessionMode.Remote` and adds a note that the technician should release control so the person at the PC can touch the hardware. That note is not a gate. Phase 2 makes the gate real inside the tool host: `SessionMode.Remote` refuses `begin_interactive_test`.

The elevated repair helper is a separate path and stays off the model. `AgentCommand.Helper` runs `AgentAdminHost.RunHelperModeAsync`, which hosts `AdminPipeServer` for a parent `RemotePCDiagnostics.Host.exe`. `AdminPipeFraming` ops are `ping`, `run_command`, and `read_sensors`. `run_command` is limited to `AdminCommandAllowlist` (sfc, dism, ipconfig, powershell, shutdown, and the other system tools listed there). `read_sensors` returns a `SensorSnapshot` from `LhmSensorProvider` inside the helper. MCP tools call `DiagnosticsService` and `IElevatedCommandBridge.ReadSensorsAsync`. They do not gain `OpRunCommand`.

## Phase 1 — read-only MCP tools, local clients

### What gets built

A local MCP server the person at the PC can attach to Cursor or Claude Desktop. It exposes read-only tools over the modules that already run, plus a stress-test start that does not run until the person at the PC approves it on screen.

Proposed tools:

| Tool | Calls | Returns |
| --- | --- | --- |
| `get_inventory` | `OsqueryModule` / `HardwareInventory.CollectAsync` through `OsqueryRunner` | The four fixed queries already in `HardwareInventory`: `SystemSql` (`system_info`), `CpuSql` (`cpu_info`), `MemorySql` (`memory_devices`), `DiskSql` (`disk_info`), mapped to `SystemInfo`, `CpuInfo`, `MemoryDevice`, `DiskInfo`. The friendly summary from `OsqueryModule.Summarize`. Query text, exit codes, and stderr stay in the log, which is what `InventorySection` already does. |
| `get_temps_and_fans` | `LibreHardwareMonitorModule` via `ISensorProvider` (`LhmSensorProvider` in the Host, or `IElevatedCommandBridge.ReadSensorsAsync` when the Host is not elevated) | One `SensorReport`: CPU, GPU, storage, board, and fan groups from `LibreHardwareMonitorModule.GroupDefs`, plus `LibreHardwareMonitorModule.Summarize`. One snapshot. No live stream. |
| `list_recent_crashes` | `CrashesModule` | Application Error 1000 and Application Hang 1002 for `CrashesModule.Days` (30), capped by `CrashesModule.Max` (500), with the tool response trimmed to `CrashesModule.RecentDays` (7) unless the caller asks for the full window. Blue screens stay a separate optional read of `BsodHistoryModule`, which `CrashesModule` already runs when `includeSystemCrashes` is set. |
| `run_disk_check` | `DriveHealthModule` (`ModuleSlugs.DriveHealth`) | Per-drive `DriveHealth` from Windows Storage (`MSFT_PhysicalDisk` and reliability counters), with the osquery `disk_info` fallback the module already uses when storage health is unavailable. This is the health check. Disk throughput is `DiskSpeedModule` and goes through `start_stress_test`. |
| `start_stress_test` | `DiagnosticsService.RunAsync` for one slug in `DiagnosticsService.StressOrder`, or `RunStressSuiteAsync` for `StressSuiteMode.Short` or `Extended` | Accepted only after on-screen approval (safety model). Progress is `StressSuiteProgress.Headline`. |
| `get_test_result` | `ResultStore.Get` and, for a suite, `DiagnosticsService.LastStressSuiteProgress` | The stored `DiagnosticResult` (`ModuleName`, `Status`, `Message`, `Timestamp`) and the suite headline. Reading the store does not start a test. |

A seventh tool, `list_modules`, returns `ModuleDescriptor` slug, display name, and kind for the catalog `DiagnosticsService` already holds, so the model asks for a real `ModuleSlugs` value. Check-group modules (`CheckGroup.Checks`) are readable through the same `RunAsync` path. Their results are summaries, with the same field cap as crashes.

Cursor and Claude Desktop spawn a process and speak MCP on stdio. The service process (`AgentCommand.Run`, session 0) cannot be that stdio peer. The IDE-facing process is a user-session child of the IDE. It talks to the running Host, or to the elevated helper the Host already starts, over 127.0.0.1 or a named pipe with a per-boot token. The pipe pattern to copy is `AdminPipeServer`: expected client exe, parent pid, and client SID, framed by `AdminPipeFraming`.

Tool handlers run where the modules already run: inside the Host (`HostServices`) when the window is open, and through `ReadSensorsAsync` plus `OsqueryRunner` when only the helper is up. `AgentHubWorker` keeps doing enrollment, heartbeats, and `LaunchCommand`. It does not load `DiagnosticsService` today, and phase 1 leaves that split in place.

### Technical tasks

| Task | Rough effort |
| --- | --- |
| Stdio MCP process plus a loopback listener bound to 127.0.0.1, with a per-boot token and the same client checks `AdminPipeServer` already does | 3 days |
| Tool schemas that call `DiagnosticsService.RunAsync` / `ResultStore.Get` / `HardwareInventory.CollectAsync` / `LibreHardwareMonitorModule` / `CrashesModule` / `DriveHealthModule` and return trimmed JSON | 4 days |
| `start_stress_test` approval: a banner in `MainLayout` when the window is open, otherwise `Win32Session.ShowConsentMessageBox` (the prompt `AgentCommand.Consent` already shows). Decline and timeout leave the test unstarted | 2 days |
| Deny-list in the tool host, and one `ChangeRecord` per call in `FileChangeJournal` (see safety) | 2 days |
| xUnit coverage with the existing fakes (`ScriptedLauncher`, `UnavailableSensorProvider`, `MemoryChangeJournal`) | 2 days |

About **2 to 3 weeks** for someone who already works in `HostServices` and `DiagnosticsService`. No change to `agent.proto`.

### Dependencies

- `DiagnosticsService`, `ResultStore`, `ModuleSlugs`, `ModuleIds`.
- `OsqueryModule` and the bundled `osqueryi.exe` (CI already checks that the Host output contains it). `OsqueryModule.ToolMissingMessage` is the user-facing failure when the binary is absent.
- `LhmSensorProvider` and `LibreHardwareMonitorModule`. CPU MSRs and SuperIO fans need administrator rights; `SensorReport` already says so when `SensorSnapshot.IsElevated` is false. PawnIO is the optional WHQL driver `LhmSensorProvider` probes. The tool reports the summary either way.
- `CrashesModule` reads the Application log through `WindowsEventLog`. In the restricted module host that read is the host query `eventlog.query`. The MCP host uses the in-process module, which needs the elevated app or the helper.
- `DriveHealthModule` needs `SystemCommandRunner` and `OsqueryRunner`.
- Stress modules need a free suite: `DiagnosticsService.IsStressSuiteRunning` and `IsAnyStressRunning` already block a second suite. `DiskSpeedModule` writes a temp file and deletes it in `CleanupAsync`. `MemoryTestModule` launches `RemotePCDiagnostics.MemTest`.
- The journal write needs the Host to be allowed to update `%ProgramData%\RemotePCDiagnostics\state` (`ProtectedState`). A standard-user MCP child cannot write `changes.json` itself; the Host writes the record.

### Risks

- A second Host started by the IDE would fight the single-instance app (`App.ExitAlreadyRunning`). The MCP child attaches to the running Host. It does not launch another `RemotePCDiagnostics.Host.exe`.
- `MemoryChangeJournal.Add` keeps only the oldest record for a `ChangeKind` and `Target`. Logging every call needs the journal change in the safety section, or later calls disappear and `UndoService` can erase the ones that used `ChangeKind.NotUndoable`.
- `start_stress_test` heats the PC and, for disk, writes a large temp file. Shipping it as a silent read-only tool would violate the safety model. The tool exists in phase 1 and runs only after the on-screen allow.
- `get_temps_and_fans` can take a couple of seconds while `LhmSensorProvider` opens LibreHardwareMonitor. The tool waits for one `Read`. It does not poll.
- Crash and osquery strings are attacker-controlled text (a crashing program picks its name). They are data in the tool result. See prompt injection below.
- Loopback HTTP without the per-boot token would let any local process drive stress tests. The token is mandatory before the listener binds.

### Success criteria

- From Cursor or Claude Desktop on the same PC, `get_inventory`, `get_temps_and_fans`, `list_recent_crashes`, and `run_disk_check` return the same summary the matching page shows, for a machine where those modules already pass.
- `get_test_result` after a UI-started CPU test matches `ResultStore.Get(ModuleSlugs.CpuStress)`.
- `start_stress_test` does not start `CpuStressTest` until the person at the PC allows it. Cancel and timeout leave `IsAnyStressRunning` false.
- A second local process without the token cannot call any tool.
- `SessionMode.Remote` can call the four read tools and `get_test_result`. It cannot call `start_stress_test`.
- Each call appends a journal record the next `UndoService.UndoAllAsync` does not delete.
- `agent.json` and the enrollment key never appear in a tool result or in `agent-status.json`.

## Phase 2 — guided interactive tests, local only

### What gets built

The model calls `begin_interactive_test`. The Blazor UI shows a prompt and buttons. The person's answer is the tool result.

The first tests are the ones on `/interactive`:

| Test | Existing UI | What the person does |
| --- | --- | --- |
| Keyboard matrix and rollover | `PhysicalBenchQaCard` capture zone, stored on `PhysicalBenchQaService` / `PhysicalBenchQaSnapshot` | Presses keys. The card already records unique keys and peak rollover. |
| Display dead pixels and touch | `PhysicalBenchQaCard` solid colors and touch points | Looks at the colors, taps the screen. Outcome is `PhysicalCheckOutcome`. |
| Webcam | `WebcamTestModule` through `IWebcamIo`. `HostServices` passes `showPreview: true` to `MediaCaptureWebcamIo` only in `SessionMode.Local` | Confirms the live preview on the PC. The remote browser does not get the preview today, and phase 2 keeps it that way. |
| Mic to speaker, speaker to mic | `MicToSpeakerModule`, `SpeakerToMicModule` | Speaks or listens, then marks pass or fail. |

The prompt is a new component on `InteractiveTestsPage` (and a banner in `MainLayout` so it is visible from any route). It uses the classes those pages already use: `card`, `banner`, `btn-small`, `btn-primary`, `chip`. No new theme, no new badge color.

The tool waits until the person clicks a button, or until a timeout (the same idea as agent consent timing out into `ConsentOutcome.TimedOut`). The result is the outcome plus the snapshot fields that already exist (`UniqueKeysPressed`, `PeakKeyRollover`, `SolidColorsInspected`, `MaxTouchPoints`, notes).

`begin_interactive_test` throws a tool error when `ISessionContext.Mode` is `SessionMode.Remote`, including when the remote user has been given control. Control and mode are different: `ShareControl` moves who drives the UI; `SessionMode` is how the process was launched (`-u=` / `REMOTEPC_MODE`). Interactive tools follow mode. The badge tooltip is the rule.

### Technical tasks

| Task | Rough effort |
| --- | --- |
| A single pending-prompt queue the page and `MainLayout` both render, with Allow / Fail / Skip and a cancel that unblocks the tool | 4 days |
| Adapters for `PhysicalBenchQaService`, `WebcamTestModule`, `MicToSpeakerModule`, `SpeakerToMicModule` so the model starts the test the buttons already start | 3 days |
| Hard `SessionMode.Local` check, busy check (`DiagnosticsService.IsStressSuiteRunning` already disables the webcam Start button), and timeout | 2 days |
| Tests around the queue and the remote refusal | 2 days |

About **2 weeks** after phase 1. The MCP transport and the journal hook are already there.

### Dependencies

- Phase 1 tool host and the on-screen approval UI.
- `InteractiveTestsPage`, `PhysicalBenchQaCard`, `PhysicalBenchQaService`.
- `WebcamTestModule`, `MicToSpeakerModule`, `SpeakerToMicModule`, and `ModuleDetailsBase` (shared start/stop for the stress and media pages).
- A live Blazor circuit in the Host window. There is no interactive test without that window, because the person has to see the prompt and the camera preview.

### Risks

- The MCP call blocks while the person walks away. The timeout must complete the tool call. A stuck call would pin a studio session and leave `WebcamTestModule` running. Cancel goes through the module stop the pages already call.
- Two prompts at once. The queue holds one. A second `begin_interactive_test` gets a busy error, matching `IsStressSuiteRunning`.
- Remote technicians will ask for these tests. The refusal text tells them to hand the keyboard to the person at the PC and use a local session. The tool still refuses in `SessionMode.Remote`.
- Keyboard capture in `PhysicalBenchQaCard` needs focus on the capture zone. The prompt has to move focus there the way the card's Capture keys button does, or the model will record zero keys and call the keyboard failed.

### Success criteria

- In a local session, a scripted MCP client calls `begin_interactive_test` for the keyboard check, the page shows the prompt, a button click returns `PhysicalCheckOutcome` to the client, and `PhysicalBenchQaService.Current` matches that answer.
- The same call during `SessionMode.Remote` returns an error and does not change `PhysicalBenchQaSnapshot`.
- Closing the preview or pressing the existing Cancel button ends the webcam tool call.
- A  remote viewer on `/mirror/<id>` never sees the camera preview. `MediaCaptureWebcamIo` stays `showPreview: false` in remote sessions.
- The interactive page looks like it does today, with one extra prompt card. Navigation, badges, and the session bar (`rbwv-session-controls`) are unchanged.

## Phase 3 — chat in the app, and AI sessions from the admin site

### What gets built

Two surfaces, one policy.

**Chat panel in the app.** A panel in `MainLayout.razor`, same top bar and same `NavRail`, using `card`, `banner`, and `btn` styles that are already on the pages. It is a transcript plus a text box. The model behind it is the same tool host as phases 1 and 2, so a message can trigger `get_inventory` or `begin_interactive_test` and the existing prompt appears. `CopilotHandoff` stays as it is (local WebView2 paste into Microsoft Copilot). The panel does not go through that window, and `HostServices` does not start registering `ICopilotHandoff` for remote sessions.

**AI session from the admin site.** A shop user on `https://admin.remoteblazorwebview.com` (private repo `budcribar/RemoteWebViewAdmin`) starts an AI technician against an enrolled PC. Today that site starts a human session with `AgentAdmin.StartSession` (`agent.proto`): the relay sends `LaunchCommand` on `AgentHub.Connect`, the agent runs consent (`AgentHubWorker` / `Win32Session.ShowConsentMessageBox` unless the ceiling is `ConsentCeiling.Unattended`), then launches `RemotePCDiagnostics.Host.exe` with `-u=` and `-g=`. An AI session is another launch on that path, with a flag the Host reads as "open the chat panel". The contract change belongs to `budcribar/RemoteBlazorWebView` (`src/Protos/agent.proto`), then a verbatim copy into this repo and into RemoteWebViewAdmin, which is how `agent.proto` is owned today.

The shop gate is trial versus MSP:

- This repo only knows active versus inactive. `ShopBrandingDto.Active` and HTTP 402 (`ShopReportPublishResult.PaymentRequired`) already block branding and report publish when the subscription or trial is off. The UI copy on `WorkflowPage` and `BrandingCertificatePage` says to renew on the relay `/shop` portal.
- Trial versus MSP is not a field on `ShopBrandingDto`. The admin site and the relay decide the tier before `StartSession`. The relay's embedded server options name `IShopStripeClient` as the billing client a test can replace (`RemoteWebViewServer` in `budcribar/RemoteBlazorWebView`). This repo does not contain that type.
- A trial shop can use phase 1 read-only tools from a local MCP client. An MSP shop can start the admin-site AI session. An inactive shop (402) can start neither remote session.

Remote AI sessions stay on the read-only tool set. `begin_interactive_test` and `start_stress_test` still require `SessionMode.Local` and an on-screen allow. The person at the PC can take control with the existing session bar and run interactive tests themselves. The model does not click those buttons in a remote session.

### Technical tasks

| Task | Rough effort |
| --- | --- |
| Chat panel in `MainLayout`, wired to the phase 1 tool host, local and remote, without new colors or a new nav destination unless the panel needs a route | 5 days |
| Model adapter: shop-supplied key, or the admin-provided key, with the caps in the billing section | 4 days |
| `agent.proto` addition (relay repo, then the copy here) so `StartSession` can ask for an AI session and the Host opens the panel. Consent and `LaunchCommand.group` stay as they are | 4 days |
| RemoteWebViewAdmin button on the Computers page, hidden unless the shop tier allows it | 4 days |
| Relay enforcement: reject the AI launch with the same 402 the report publish already returns when the shop is inactive or not MSP | 3 days |

About **4 weeks** across the three repos. The app panel is the first slice (about a week) and can ship before the admin-site button.

### Dependencies

- Phases 1 and 2 for tools and the local prompt.
- `AgentAdmin.StartSession`, `LaunchCommand`, `AgentHubWorker`, `ConsentCeiling`, `ActiveSessionInfo`.
- `ShopRelayClient`, `ShopBrandingDto`, the 402 path, `ShopRelayClient.ApiKeyPrefix` (`rpd_live_`).
- RemoteWebViewAdmin and the relay. Neither is modified by this proposal's PR.
- Stripe billing already used for shop subscriptions, reached through `IShopStripeClient` on the relay. Tier rules live there.

### Risks

- A contract change in `agent.proto` has to land in three repos together. An old agent that ignores an unknown field is safe only if the new flag is optional and the default remains today's human `StartSession`.
- The chat panel must not cover `rbwv-session-controls` or the agent badge (`data-testid="agent-mode-badge"`). Those are how the person sees who is connected.
- Remote latency: a tool that round-trips the full `SensorSnapshot` or 500 crash rows on every turn will feel stuck. The host sends the summaries phase 1 already returns. See transport.
- Putting the model key in `agent.json` or `agent-status.json` would expose it to every reader of those files (`agent-status.json` is readable by Users). Keys stay out of both files.
- Trial shops will try the admin button. The server refuses. Hiding the button is not the control.

### Success criteria

- The panel opens in a local session, sends `get_inventory`, and shows the `OsqueryModule` summary. Layout, badge classes, and nav links match the current app.
- `CopilotHandoff` still works from the area page in a local session and still is not registered in a remote session.
- An MSP shop can start an AI session from the admin site. The PC shows the existing consent prompt unless the agent is `ConsentCeiling.Unattended`. The Host comes up in `SessionMode.Remote` with the panel open, and `begin_interactive_test` returns the phase 2 error.
- A trial shop's local MCP client can call the phase 1 read tools. The admin site refuses the AI session for that shop.
- An inactive shop (branding not active, or 402) cannot start the AI session.
- Tool traffic for a remote session is authenticated with the relay ticket described below. A missing ticket never reaches `DiagnosticsService`.

## Safety model

Read-only first. Anything that changes the PC waits for the person at the screen. The model does not get a shell.

**Read-only tools** are `get_inventory`, `get_temps_and_fans`, `list_recent_crashes`, `run_disk_check`, `get_test_result`, and `list_modules`. They call `RefreshAsync` on check modules and read `ResultStore`. They do not call `RemediationService`, `WorkflowService`, `ServiceActionService`, or `UndoService`.

**On-screen approval** is required before `start_stress_test`, before `begin_interactive_test`, and before any later tool that writes a setting. The person at the PC sees what will happen (the `ServiceActionPlan` shape: title, what will happen, warning) and clicks Allow. Timeout means no. In a remote session the host refuses these tools even if the remote user has control.

**Hard deny-list**, enforced in the tool host, not in the prompt:

- No free-form process start. `OsqueryRunner` runs only `HardwareInventory`'s fixed SQL. There is no `run_query` tool.
- No `AdminPipeFraming.OpRunCommand`, even though `AdminCommandAllowlist` would constrain it. PowerShell, `reg.exe`, `shutdown.exe`, and `schtasks.exe` stay on the helper's list for the app's own repairs and off the model's list.
- No registry write. `RegistryAllowlist` is the app's own undo set, not an MCP allow-list.
- No scheduled-task change (`ScheduledTaskAllowlist`).
- No file delete, no `DiskSpeedModule` temp file except inside an approved `start_stress_test`, no `UndoService.UndoAllAsync`, no `--undo-all`.
- No read or write of `AgentConfig` / `agent.json`, and no write of `agent-status.json`. `AgentStatusPublisher` remains the only writer.
- Module arguments are `ModuleSlugs` constants the catalog actually loaded. An unknown slug is an error.

**Journal.** Every tool call is a `ChangeRecord` in the existing `FileChangeJournal` (`ProtectedState.ChangesFile`), with `Actor` set from `ServiceActor.From(session)` for a human click and `"AI technician"` for a model call. `ChangeRecord.Label` is the tool name and the slug.

The journal as it stands will not keep that history. `MemoryChangeJournal.Add` drops a second record with the same `ChangeKind` and `Target`, and `UndoService.UndoAllAsync` removes records it skipped (`ChangeKind.NotUndoable` is reported once, then forgotten). Phase 1 adds audit records that `UndoService` lists and does not delete, and that `Add` does not collapse. They live in `changes.json` with the undo records. They are not a second log. A reversible setting change, if one is ever added later, is still a normal `ChangeRecord` with `Previous` filled in, so Undo still puts it back.

**Remote sessions stay read-only.** `SessionMode.Remote` allows the read-only tools and refuses `start_stress_test` and `begin_interactive_test`. That matches `AgentMode.Tooltip` and is stronger than today's UI, which still lets a controlling remote user press the interactive buttons. Those buttons can stay for the person at the PC. The model cannot press them remotely.

**Prompt injection.** Tool output is untrusted: crash module names, event messages, osquery vendor strings, `ShopBrandingDto` text, disk serials. The model is told to treat tool results as data. The host does not rely on that. The deny-list and the `SessionMode` check run in code on every call, after the model has seen the text. A crash row that says to run `powershell.exe` or to undo the journal does not become a tool argument. Results are size-capped (crash list trimmed, sensor summary instead of every `SensorReading` sample, no stderr from `InventorySection.RawStdErr` in the model payload).

## Billing and which model runs

Two ways a shop pays for the model. The tools are the same either way.

**The shop brings a key.** The key is a user secret for the signed-in Windows user (the architecture rule for settings that belong to that user: their hive, not the elevated account's, and not `agent.json`). The local MCP client and the in-app panel call that shop's model. Cursor or Claude Desktop on the bench can also use the shop's own subscription with no key stored in this app: phase 1 stdio works with whatever model the IDE is already using. Cost sits on the shop's provider bill. The host still caps tool calls per session so a poisoned crash log cannot loop `get_inventory` all day.

**Admin-provided, paid MSP feature.** The admin site holds the provider key and bills the shop through the Stripe integration the relay already seams with `IShopStripeClient`. The in-app panel and the remote AI session use that key only after the tier check. Trial shops keep local read-only MCP and do not get the hosted model. MSP shops get the hosted model and the admin-site launch. Inactive shops get neither. This repo already stops report publish on 402; the AI launch uses that same answer.

**Cost control**, for both:

- Send summaries: `LibreHardwareMonitorModule.Summarize`, `OsqueryModule.Summarize`, `StressSuiteProgress.Headline`, crash rows for `RecentDays`. Do not stream `LhmSensorProvider.Read` on a timer, and do not put samples on the agent heartbeat (`AgentSessionOptions.HeartbeatInterval` is 30 seconds).
- Cache: if `ResultStore` has a fresh result, `get_test_result` and the read tools return it instead of running the module again. The caller can pass a refresh flag. Refresh still counts as a tool call.
- Per-shop daily cap on hosted tokens and on tool calls, enforced on the relay for remote sessions and in the Host for local hosted calls. When the cap is hit the tool returns a clear error and the panel says the shop is over its allowance. A BYO key is not metered by us, and the tool-call cap still applies.
- Stress and interactive tools are off in remote hosted sessions, which also keeps a remote model from starting a 5-minute `StressSuiteMode.Extended` run on every machine in the fleet.

Which provider (the shop's model versus the admin-site model) is an open question below. The tool host does not care. It returns JSON either way.

## Remote vs local transport and auth

**Local.** Cursor and Claude Desktop spawn the MCP process and use stdio. That process connects to the Host on 127.0.0.1 or a named pipe. The listener binds loopback only, requires the per-boot token, and checks the client the way `AdminPipeServer` checks parent exe and SID. A LAN interface is not bound. The enrollment key is not an MCP credential. `AgentHubWorker` stays on `AgentHub.Connect` for human launches and does not carry tool traffic.

**Remote.** The admin site and the in-app panel, when the session is remote, send tool calls through the RemoteBlazorWebView relay at `https://server.remoteblazorwebview.com:34544` (`AgentCommandLine.DefaultServer`; `SessionLaunchOptions` also accepts `https://remoteblazorwebview.com:34544`). The relay already fronts the session with `RemoteTicket` when `Authorization:Provider` is `RemoteTicket`:

- Signing key: `RelayTicket:SigningKey`, environment variable `RELAY_TICKET_SECRET`.
- Ticket on the request: cookie `rwv-relay-ticket` or header `x-relay-ticket`.
- `/mirror` without a valid ticket redirects to the login URL.
- With sign-in on, session pages open for a signed-in user whose groups include the session's `Group`.

An AI tool call uses that ticket. The relay checks the shop group against `LaunchCommand.group` / `ISessionContext.Group` / `AgentHello` and checks the MSP tier before it forwards the call to the Host. The Host checks `SessionMode` again. A ticket for another shop, or a missing ticket, never reaches `DiagnosticsService`.

The agent heartbeat is the wrong pipe for tools. `Heartbeat` carries signed-in user, `session_running`, `session_id`, and cached app version, on a 30-second timer. Tool calls need their own request/response on the relay so a read returns in one round trip. That is the `agent.proto` work in phase 3. Until it exists, remote AI sessions are not offered. Local stdio does not need it.

**Latency.** The relay is an HTTP/2 hop to Railway (port 34544). A summary payload (a few kilobytes) is the right size. A full sensor tree or a 500-row crash dump is not. The Host summarizes before the response leaves the PC. The panel shows `StressSuiteProgress.Headline` while a local approved suite runs, and the model polls `get_test_result`. It does not hold a streaming MCP connection open across the relay for fan RPM.

**Session files.** `ActiveSessionInfo` in `active-session.json` remains the human diagnostic session (process id, session id, group, mode). An MCP client attached locally does not write a second active session and does not clear the one `MainWindow` publishes.

## Open questions

1. **Which hosted model.** The admin-provided path needs a provider and a default model. The shop BYO path needs a place in the user hive and a way to test the key without logging it. Neither is chosen here.
2. **Trial stress tests.** Phase 1 allows `start_stress_test` on a local session after on-screen approval, including a trial shop's bench PC. Confirm that a trial shop may heat a machine on the bench. Remote stress stays refused either way.
3. **Interactive tests while a remote human has handed control back.** `SessionMode` stays `Remote` for the life of the process. The proposal refuses model-driven interactive tests for that whole process. Confirm the person at the PC is expected to press the existing buttons themselves, with the model only coaching in the panel.
4. **Audit records versus Undo.** Confirm audit `ChangeRecord`s stay in `changes.json` across `UndoService.UndoAllAsync` and `--undo-all`. The alternative is that Undo erases the AI history, which fails the safety criterion.
5. **Who may attach a local stdio client.** Any Windows user who can start the MCP child and read the per-boot token can call read tools. Confirm that is acceptable on a shop bench, and that a customer account on the same PC should not see the token.
6. **Voice.** `--voice` is a call between the person at the PC and a remote human. The chat panel is text. Whether an AI session also opens voice is out of this proposal.
7. **`CopilotHandoff`.** It remains for the area-page "copy for Copilot" path. Whether that button should point at the new panel later is a product choice, not part of the first three phases.
8. **Contract rollout.** An optional field on `StartSessionRequest` keeps old agents working. Confirm the relay, the admin site, and this agent ship that field in one release rather than inferring AI mode from the requester string.

## Recommended sequence

1. **Phase 1 local read-only tools**, stdio and loopback, against a running Host. No relay change. Journal audit records and the deny-list land in the same change, before `start_stress_test` is callable.
2. **On-screen stress approval**, still local. `start_stress_test` stays dark until the banner or `Win32Session.ShowConsentMessageBox` returns allow.
3. **Phase 2 interactive prompts** on `InteractiveTestsPage` / `MainLayout`, `SessionMode.Local` only.
4. **Chat panel** in the current layout, talking to the same tool host. `CopilotHandoff` untouched.
5. **Admin-site AI session last**: `agent.proto`, relay ticket check, Stripe tier (trial versus MSP, and 402 when inactive), then the Computers-page button in RemoteWebViewAdmin. Remote sessions stay on the read-only tool list.

Steps 1–4 are this repo. Step 5 is this repo plus `budcribar/RemoteBlazorWebView` and `budcribar/RemoteWebViewAdmin`. Stopping after step 4 still gives a shop a local AI technician on the bench, which is the useful first deployment.
