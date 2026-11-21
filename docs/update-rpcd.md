# update_rpcd

Remote install of an official Remote PC Diagnostics build. The fleet agent on the PC downloads the installer, checks it, installs it, and brings the app back. Admin's MCP connector does not install anything itself.

This repository does not host the Admin MCP server. `list_computers`, `get_rpcd_release`, and `get_computer_download_link` live in private `budcribar/RemoteWebViewAdmin`. `get_rpcd_release` only returns download URLs. `get_computer_download_link` is for onboarding. RemoteWebViewAdmin has to add the tool below. The relay in `budcribar/RemoteBlazorWebView` has to forward the new hub messages. Both projects copy `src/RemotePCDiagnostics.Agent/Protos/agent.proto`.

A PC keeps running its current agent until that agent is replaced. This command exists on agents built with this change. An older agent ignores the hub command (protobuf drops an unknown field) and the pipe returns "This agent cannot install RPCD updates."

## What the agent does

1. Refuses unless `approved` is true. `approvedBy` is an audit label only. It never counts as approval.
2. Refuses when a check, a fix, a stress test, or a benchmark is running, or when the service workflow is in an active stage: Checking, RestartBefore, BeforeBenchmark, Applying, RestartAfter, AfterBenchmark, or Reporting. The refusal names that stage. Review, Idle, Done, Cancelled and Failed are not running. A review parked with `running` false and `busy` false does not block the update, and it is left out of `activity-data`, which is what `get_session_status` lists. The app writes that same verdict to `sessions/rpcd-activity.json` (the folder the service already reads for the open session) and, when the admin pipe is connected, over `report_activity`. The service pipe is not one-shot: when the connection drops, the agent listens on the same pipe name again and the app drops the dead client and connects again. A hub command cannot claim the PC is idle. If the app is open and neither copy is fresh within 90 seconds, the agent waits up to 15 seconds, then refuses. The refusal detail says why the probe failed (nothing arrived, the report was too old, the clock disagreed, or the file could not be read), and the agent log lines start with `[rpcd-update]`. The agent service and an app's elevated helper also share the staging copy, the update status, and a lock file, so only one update runs.
3. Refuses when an update is already in progress, or when the requested channel is not `stable` or `prerelease`.
4. Reads the official GitHub release. `stable` is `GET https://api.github.com/repos/budcribar/RemotePCDiagnostics/releases/latest`. `prerelease` is the rolling `prerelease` tag. An explicit version must be that release, or a tag whose build version matches. Older rolling builds are replaced and are not installed.
5. Downloads only `RemotePCDiagnostics-Setup-*-win-x64.exe` from `https://github.com/budcribar/RemotePCDiagnostics/releases/download/...`. There is no CPU check and no win-arm64 asset. The installer allows x64-compatible Windows (Inno Setup 6.3 or newer), so on an ARM64 PC such as a Snapdragon X Elite it installs that x64 build, which then runs under emulation. TestShop bundles are ignored. The URL has to match that prefix. Redirects are limited to GitHub release hosts.
6. Requires the sibling `.sha256` asset. No checksum, or a checksum that does not match, deletes the partial file and does not start Setup. The installed build is unchanged.
7. Runs Setup as `/VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /NORESTART /PRESERVEAGENT` plus the current session's restart arguments when there is one. `/PRESERVEAGENT` runs `RemotePCDiagnostics.Agent.exe install` with no `--server`, `--key`, `--consent`, `--lifetime`, or `--group`, so `agent.json` keeps the machine id, enrollment key, consent, and lifetime. The agent MSI is not passed. Its custom action would run install again with empty properties and can wipe the key.
8. Setup closes the app, copies the new build, and updates the service. Setup does not start the app (no `/RELAUNCHARGS`): its `runasoriginaluser` start would inherit an elevated helper's token. The agent saves the session's restart command line first, and the restarted agent service (or the agent that ran Setup, if Setup failed) starts the app un-elevated in the signed-in user's session on the same relay session.
9. Publishes a status snapshot the caller polls. After the service is replaced, the new service reads the snapshot. If the installed version is the target, the snapshot is `succeeded` with the old and new versions. If Setup never finishes, the snapshot becomes `failed` and names the version still installed.

Inno Setup rolls back a failed file copy. A non-zero Setup exit is `failed` with that code and the version still on disk. The agent does not keep a second copy of the old installer to run backwards. If Setup closed the app and then failed, the agent starts the previous build again when it still has the session's restart command line.

## Status

`stage` is one of:

| Stage | Meaning |
| --- | --- |
| `idle` | Nothing has been requested. Not terminal. |
| `checking` | Reading the GitHub release. |
| `downloading` | `percent` is 0–100. |
| `verifying` | SHA-256. |
| `installing` | Setup is running. The app disconnects, then reconnects on its own. |
| `refused` | Approval, channel, version, or busy work. Terminal. Nothing was installed. |
| `already_up_to_date` | The PC is already on that build. Terminal. |
| `succeeded` | `oldVersion` is the build before, `newVersion` is the build now on disk. Terminal. |
| `failed` | `error` says why. The previous build is still what runs. Terminal. |

`terminal` is true for `refused`, `already_up_to_date`, `succeeded`, and `failed`.

## What RemoteWebViewAdmin adds

Add an MCP tool `update_rpcd`:

| Argument | Required | Meaning |
| --- | --- | --- |
| `computer` | yes | The computer name `list_computers` uses. |
| `channel` | yes | `stable` or `prerelease`. |
| `version` | no | Exact build, such as `1.2.0-ci.996.1`. Omit for the current release on `channel`. |
| `approved` | yes | Must be true. The tool refuses when it is false or missing. The shop owner has to approve this install. Do not set it from `updateAvailable` alone. |
| `approvedBy` | no | Short audit label, such as a role. Not a customer name, email, or computer name. |

The tool returns the first snapshot immediately (`checking`, or a terminal refusal). It does not wait for Setup. A second tool, or the same tool with no new install, polls:

`get_update_rpcd` with `computer` and optional `requestId`. Call it until `terminal` is true. While Setup replaces the app the session drops. Keep polling. `session_busy` and a missing session are normal until the app reconnects. Then `stage` is `succeeded` or `failed`, and `oldVersion` / `newVersion` are set.

Do not call `run_check`, `apply_fix`, `start_workflow`, or `run_stress_tests` on that computer while an update is `checking`, `downloading`, `verifying`, `installing`, or `relaunching`.

### Relay

`AgentAdmin.UpdateRpcd` and `AgentAdmin.WatchUpdateRpcd` are in `agent.proto`. The relay should:

1. Require the same caller authorization as `StartSession` for that `machine_id`.
2. Send `HubCommand.update_rpcd` with `channel`, `version`, `approved`, and `approved_by`. Leave `approved` false unless the MCP tool received `approved: true`.
3. Stream `AgentMessage.update_rpcd` back to `WatchUpdateRpcd`, replaying the latest snapshot first.
4. `HubCommand.update_rpcd_status` asks the agent for the current snapshot (empty `request_id` means the latest).

The agent downloads from GitHub itself. The relay must not send an installer URL or a checksum. A hint from `ReleaseAvailableCommand` is not an install.

### Parked review

`cancel_workflow` in RemoteWebViewAdmin (`HardwareInventoryWorkflow.CancelWorkflowAsync`) returns `not_running` unless the stage is RestartBefore, BeforeBenchmark, Applying, RestartAfter, AfterBenchmark, or Reporting. Review is not in that list, and the Review page does not show `wf-cancel`. That cancel aborts a restart and turns automatic sign-in off. It is the wrong action for a review that has not started.

This app clears a parked review in three ways, all of which call `WorkflowService.DismissParkedReview` and return the stage to Idle:

- `wf-start-over` on the Review page
- hidden `wf-dismiss` on the Review page (same result, for a remote caller)
- leaving the Service workflow page for any other page

RemoteWebViewAdmin should, when `workflow-data` stage is `Review` and `busy` is not true, click `wf-dismiss` (or `wf-start-over`) and wait until the stage is `Idle`. Return outcome `dismissed`. Do not return `not_running` for that case. No relay change is required: this is a browser click, not a hub RPC.

`ParseActivity` in `HardwareInventoryWorkflow.Activity.cs` lists every `activity-data` `workflow` object as a running `service_workflow`. After this build, a parked Review is omitted from that object, so a current app no longer shows it. For an older app that still emits Review, skip a workflow item whose stage is Idle, Review, Done, Cancelled, or Failed.

### Browser session

A session that is already open can start the same install without the relay change. The layout renders a hidden `update-rpcd-panel` (see [browser-contract.md](agent-guides/browser-contract.md)). Set `update-rpcd-channel`, `update-rpcd-version`, check `update-rpcd-approved`, then click `update-rpcd-start`. Poll `update-rpcd-data` until `terminal` is true. After the app reconnects, read that element again. This path still needs an agent built with this change, because the app asks the agent over the admin pipe (`update_rpcd`, `update_rpcd_status`, `report_activity`).
