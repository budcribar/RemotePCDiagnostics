# Remote PC Diagnostics agent (download-on-demand sessions)

Status (November 3, 2026):
- **Done:** the relay side (`AgentHub` / `AgentAdmin` in RemoteBlazorWebView, branch `net10`; see its `doc/Agents.md`) and the admin site's **Computers** page (RemoteWebViewAdmin).
- **Here:** the contract (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`) and the agent's pure logic library (`src/RemotePCDiagnostics.Agent.Core`: command line, config, manifest, signature, consent rule, cache, launch rules, backoff).
- **Not built yet:** the agent exe (service, install/uninstall, download, launch), `release.yml`, `tools/New-ManifestSigningKey.ps1`, and tests for the logic library.
- **Relay settings on Railway:** `PUBLIC_BASE_URL`, `AGENT_ADMIN_KEY` (without it every start asks the person at the PC), and optionally `AGENT_ENROLLMENT_KEYS`.

## Why

Today the full app (a ~300 MB single-file exe, 129 MB zipped) has to be copied to the client's PC before a technician can help. Instead, a
small **agent** stays installed. It keeps an outbound connection to the relay on Railway. When a technician picks that computer on the admin
site, the agent downloads the app (or uses its cached copy), checks it, and starts it on the signed-in user's desktop. The technician then
drives it in the browser as before.

## Decisions

| Topic | Decision |
|---|---|
| Consent | Configurable. The installer sets the **ceiling** (`--consent=ask` or `--consent=unattended`), stored locally on the PC. The relay and technicians can only be stricter: a technician may skip the prompt only when the ceiling is `unattended` and they tick "Don't ask". |
| Agent lifetime | Configurable at install: `--lifetime=persistent` (default) or `--lifetime=session`. A per-session agent uninstalls itself and deletes the cached app after one session. The change journal (`%LOCALAPPDATA%\RemotePCDiagnostics\changes.json`) is never deleted, so a later session can still undo. |
| Cache | One verified app version is kept under `%ProgramData%\RemotePCDiagnostics\app\<version>\`. It's replaced when a newer release is verified. |
| Distribution | GitHub Releases of the public RemotePCDiagnostics repo. Each release has `RemotePCDiagnostics-win-x64.zip`, `RemotePCDiagnostics.Agent.exe`, `manifest.json` and `manifest.sig`. |
| Integrity | The agent runs only an app whose zip matches the SHA-256 in `manifest.json`, and only when `manifest.json` carries a valid ECDSA P-256 signature (`manifest.sig`) from the release key built into the agent. Downloads come only from `github.com/budcribar/RemotePCDiagnostics/releases/...` (and GitHub's redirect host for release assets). |
| Code signing | For now: none / self-signed. A free trusted certificate (SignPath Foundation, which needs an OSI license; the repo is MIT) can be added later. The manifest signature is the actual security control. |
| License | MIT. |

## Pieces

1. **Agent** (`src/RemotePCDiagnostics.Agent`, this repo).
   - A NativeAOT, trimmed, single-file Windows exe. The same exe is the installer, the Windows service and the consent prompt. Target size: under 15 MB.
   - It connects to the relay's `AgentHub.Connect` gRPC stream (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`, copied from the relay).
2. **Relay** (`RemoteWebViewService` in budcribar/RemoteBlazorWebView).
   - It implements `AgentHub` (for agents, native gRPC) and `AgentAdmin` (for the admin site, gRPC-Web).
   - The registry is in memory. Optionally, `AGENT_ENROLLMENT_KEYS` (comma-separated) restricts which installs may register; when it isn't set, any key is accepted.
3. **Admin site** (budcribar/RemoteWebViewAdmin).
   - A **Computers** page lists agents (online status, last seen, user, OS, versions, consent ceiling, session).
   - **Start diagnostics** shows live progress and opens `<server>/app/<session>` when the app is ready.
4. **Release workflow** (`.github/workflows/release.yml`, this repo).
   - Runs on tag `v*` or manually. It builds the app and the agent, writes and signs the manifest, and publishes the GitHub release.

## Session flow

1. The technician clicks **Start diagnostics**, which calls `AgentAdmin.StartSession(machine_id, unattended)`.
2. The relay creates `session_id` (GUID) and `request_id`, and sends `LaunchCommand` down that agent's stream.
3. The agent asks for consent unless allowed to skip it. It runs `RemotePCDiagnostics.Agent.exe consent ...` in the user's session, and the person clicks Allow/Deny within 2 minutes.
4. The agent fetches `releases/latest/download/manifest.json` and `manifest.sig`, verifies the signature, then uses the cached app or downloads the zip and checks its SHA-256. Each step is reported as `LaunchProgress`.
5. The agent starts `RemotePCDiagnostics.Host.exe -u=<server_url> -i=<session_id>` as the signed-in user with their **elevated** token (no UAC prompt). If nobody is signed in, it reports FAILED with "Nobody is signed in".
6. When the app shows up on the relay under `session_id`, the relay reports READY (or the agent does, once the process is up and the relay's `/status/<id>` answers). The admin site opens `/app/<session_id>`.
7. When the app exits, the agent reports ENDED. A per-session agent then removes itself.

## Manifest

`manifest.json` (UTF-8, signed byte-for-byte; the signature is base64 IEEE P1363 ECDSA P-256 / SHA-256 in `manifest.sig`):

```json
{
  "product": "RemotePCDiagnostics",
  "version": "1.2.0",
  "file": "RemotePCDiagnostics-win-x64.zip",
  "url": "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.2.0/RemotePCDiagnostics-win-x64.zip",
  "size": 129342616,
  "sha256": "<64 hex>",
  "entry": "RemotePCDiagnostics.Host.exe",
  "published": "2026-11-03T22:00:00Z"
}
```

## Agent command line

```
RemotePCDiagnostics.Agent.exe install [--server=https://server.remoteblazorwebview.com:34544] [--key=<enrollment key>]
                                      [--consent=ask|unattended] [--lifetime=persistent|session]
RemotePCDiagnostics.Agent.exe uninstall
RemotePCDiagnostics.Agent.exe status
RemotePCDiagnostics.Agent.exe run            (what the service runs; also usable in a console for testing)
RemotePCDiagnostics.Agent.exe consent ...    (internal: the prompt shown on the user's desktop)
```

`install` needs administrator rights (it relaunches itself elevated). It:
- copies itself to `%ProgramFiles%\RemotePCDiagnostics Agent\`
- writes `%ProgramData%\RemotePCDiagnostics\agent.json` (machine id, server, key, consent, lifetime), with write access limited to Administrators and SYSTEM
- registers and starts the `RemotePCDiagnosticsAgent` service (automatic, delayed start, restart on failure)

## One-time setup (owner)

1. Make the repo public (GitHub → Settings → General → Danger Zone → Change visibility → Public).
2. Create the release signing key: run `tools/New-ManifestSigningKey.ps1` on your PC, from the repo folder.
   - It creates the key, stores the private key as the `MANIFEST_SIGNING_KEY` Actions secret (with `gh` if it's installed, otherwise it copies the key to the clipboard and opens the secrets page), and writes the public key into `src/RemotePCDiagnostics.Agent/ManifestKey.cs`.
   - Commit that file. The private key is never written to disk.
3. Tag a release (`git tag v1.2.0 && git push origin v1.2.0`) or run the Release workflow manually.

Until step 2 is done, the agent registers and shows up on the admin site, but it refuses to start the app ("release signing key not set up").

## Phases

1. **(this)**
   - The agent service with install/uninstall and consent.
   - Download, verify and cache, then launch as the signed-in user.
   - The relay registry, the admin Computers page, and the release workflow.
2. Credentials per install instead of shared enrollment keys, technician permissions per PC, an audit log, and the agent updating itself.
3. Restarts during a session: the agent relaunches the app after boot when the workflow is mid-restart, instead of the app's RunOnce entry. Also undo through the agent (`--undo-all` with the cached app).
