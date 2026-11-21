# update_rpcd

Remote install of an official Remote PC Diagnostics build. The fleet agent on the PC downloads the installer, checks it, installs it, and brings the app back. Admin's MCP connector does not install anything itself.

This repository does not host the Admin MCP server. `list_computers`, `get_rpcd_release`, and `get_computer_download_link` live in private `budcribar/RemoteWebViewAdmin`. `get_rpcd_release` only returns download URLs. `get_computer_download_link` is for onboarding. RemoteWebViewAdmin has to add the tool below. The relay in `budcribar/RemoteBlazorWebView` has to forward the new hub messages. Both projects copy `src/RemotePCDiagnostics.Agent/Protos/agent.proto`.

A PC keeps running its current agent until that agent is replaced. This command exists on agents built with this change. An older agent ignores the hub command (protobuf drops an unknown field) and the pipe returns "This agent cannot install RPCD updates."

## What the agent does

1. Refuses unless `approved` is true. `approvedBy` is an audit label only. It never counts as approval.
2. Refuses when a check, a fix, the service workflow (including while it waits at review), a stress test, or a benchmark is running. The app reports that over the admin pipe when it changes and every 30 seconds. A hub command cannot claim the PC is idle. If the app is open and the report is missing or older than 90 seconds, the agent refuses rather than guess. The agent service and the app's elevated helper share the report, the update status, and a lock file in the admin-only staging folder, so whichever one the app talks to, both see the same state and only one update runs.
3. Refuses when an update is already in progress, or when the requested channel is not `stable` or `prerelease`.
4. Reads the official GitHub release. `stable` is `GET https://api.github.com/repos/budcribar/RemotePCDiagnostics/releases/latest`. `prerelease` is the rolling `prerelease` tag. An explicit version must be that release, or a tag whose build version matches. Older rolling builds are replaced and are not installed.
5. Downloads only `RemotePCDiagnostics-Setup-*-win-x64.exe` from `https://github.com/budcribar/RemotePCDiagnostics/releases/download/...`. TestShop bundles are ignored. The URL has to match that prefix. Redirects are limited to GitHub release hosts.
6. Requires the sibling `.sha256` asset. No checksum, or a checksum that does not match, deletes the partial file and does not start Setup. The installed build is unchanged.
7. When this process is the agent service (session 0), it closes `RemotePCDiagnostics.Host` and waits until `Global\RemotePCDiagnostics.Host` is gone. A technician session is that Host. Silent Setup checks the mutex during initialization, before `CloseApplications`, and `/SUPPRESSMSGBOXES` answers the prompt with Cancel, so Setup exits 1 and changes nothing. The elevated helper does not close the Host itself (it sits in the Host's kill-on-close job). Setup's script closes the Host after Setup has left that job, with `taskkill /F /IM` and not `/T`, so a Setup process that is a descendant of the Host is not killed with it.
8. Runs Setup as `/VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /FORCECLOSEAPPLICATIONS /NORESTART /PRESERVEAGENT /LOG="<staging>\rpcd-setup.log"`. `/PRESERVEAGENT` runs `RemotePCDiagnostics.Agent.exe install` with no `--server`, `--key`, `--consent`, `--lifetime`, or `--group`, so `agent.json` keeps the machine id, enrollment key, consent, and lifetime. The agent MSI is not passed. Its custom action would run install again with empty properties and can wipe the key. There is no `/RELAUNCHARGS`.
9. Setup copies the new build and updates the service. The agent saves the session's restart command line first, and the restarted agent service (or the agent that ran Setup, if Setup failed) starts the app un-elevated in the signed-in user's session on the same relay session.
10. Publishes a status snapshot the caller polls. After the service is replaced, the new service reads the snapshot. If the installed version is the target, the snapshot is `succeeded` with the old and new versions. If Setup fails, the snapshot is `failed` and includes `installerExitCode` and `installerLog` (the masked tail of the `/LOG` file, about the last 200 lines). The same exit code and tail are written to the agent log. If Setup never finishes, the snapshot becomes `failed` and names the version still installed.

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
| `failed` | `error` says why. When Setup ran, `installerExitCode` is its exit code and `installerLog` is the masked log tail. The previous build is still what runs. Terminal. |

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

`get_update_rpcd` with `computer` and optional `requestId`. Call it until `terminal` is true. While Setup replaces the app the session drops. Keep polling. `session_busy` and a missing session are normal until the app reconnects. Then `stage` is `succeeded` or `failed`, and `oldVersion` / `newVersion` are set. On `failed`, pass through `installerExitCode` and `installerLog` from the snapshot. Do not drop them. `installerLog` is already masked.

Do not call `run_check`, `apply_fix`, `start_workflow`, or `run_stress_tests` on that computer while an update is `checking`, `downloading`, `verifying`, `installing`, or `relaunching`.

### Relay

`AgentAdmin.UpdateRpcd` and `AgentAdmin.WatchUpdateRpcd` are in `agent.proto`. The relay should:

1. Require the same caller authorization as `StartSession` for that `machine_id`.
2. Send `HubCommand.update_rpcd` with `channel`, `version`, `approved`, and `approved_by`. Leave `approved` false unless the MCP tool received `approved: true`.
3. Stream `AgentMessage.update_rpcd` back to `WatchUpdateRpcd`, replaying the latest snapshot first.
4. `HubCommand.update_rpcd_status` asks the agent for the current snapshot (empty `request_id` means the latest).
5. Copy `agent.proto` again. `UpdateRpcdProgress` now has `installer_log` (field 10) and `optional int32 installer_exit_code` (field 11). `WatchUpdateRpcd` has to deliver both. Re-serializing the protobuf message after regenerating from this file is enough. A hand-mapped DTO has to copy `installer_log` to `installerLog` and `installer_exit_code` to `installerExitCode`, including when the exit code is 0.

The agent downloads from GitHub itself. The relay must not send an installer URL or a checksum. A hint from `ReleaseAvailableCommand` is not an install.

### Browser session

A session that is already open can start the same install without the relay change. The layout renders a hidden `update-rpcd-panel` (see [browser-contract.md](agent-guides/browser-contract.md)). Set `update-rpcd-channel`, `update-rpcd-version`, check `update-rpcd-approved`, then click `update-rpcd-start`. Poll `update-rpcd-data` until `terminal` is true. After the app reconnects, read that element again. This path still needs an agent built with this change, because the app asks the agent over the admin pipe (`update_rpcd`, `update_rpcd_status`, `report_activity`).
