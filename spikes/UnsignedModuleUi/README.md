# Spike: unsigned module UI in a sandboxed iframe

This spike answers the open question in the dynamic module loading plan. Can an unsigned module's own Razor UI run in a
**restricted-token, Medium-integrity** RemoteBlazorWebView process, and can the app frame it over the **embedded relay** in a
**sandboxed iframe**, with a **postMessage** channel?

It is not part of `RemotePCDiagnostics.sln`, because it needs RemoteBlazorWebView packages built from `net10` with
`PeakSWC.RemoteWebViewService.Lib`.

## Build (Windows)

1. Build the packages from a RemoteBlazorWebView clone on `net10` (with budcribar/RemoteBlazorWebView#64) that has the JS bundle (`src/RemoteWebView.Blazor.JS/dist`), for example:
   `dotnet pack src/RemoteWebViewService.Lib -c Release -p:Version=10.0.14-embedded.2 -o <repo>/third_party/RemoteBlazorWebView/packages`.
   Do the same for `src/RemoteWebView` and `src/RemoteBlazorWebView.Wpf`.
2. `dotnet build spikes/UnsignedModuleUi/Shell -c Release` (this also builds the module UI host and copies it into `moduleui\` next to the shell)
3. Run `spikes/UnsignedModuleUi/Shell/bin/Release/net10.0-windows10.0.19041.0/win-x64/UnsignedUiSpike.Shell.exe`, or add `--unrestricted` for a control run with a normal token.

## What it shows

The shell starts two in-process relays: one **open**, and one **locked** with `FrameAncestors` set to the shell's origin. It then starts three module UI hosts with
the app's real `RestrictedModuleHostLauncher` token (Administrators deny-only, no privileges, Medium integrity), and frames each
one under an app-drawn banner:

| Frame | Relay | Sandbox |
|-------|-------|---------|
| open | open | `allow-scripts allow-forms` (opaque origin) |
| locked | locked | `allow-scripts allow-forms` (opaque origin: the relay sees `Origin: null`) |
| samesrc | locked | adds `allow-same-origin` (keeps the relay's origin, still cross-origin to the shell) |

Each module page reports the following to the shell with `postMessage`:
- its pid, integrity level and admin state
- sandbox probes: reading `window.top`, `localStorage`, cookies, `window.open`, `alert`

The shell can post to each frame and tries to read each frame's document. **Save results** writes
`%LOCALAPPDATA%\RemotePCDiagnostics\spike\results-*.json`, and each module host logs to `spike\modulehost\<frame>\module-ui.log`.

## Results (2026-11-05, Budslaptop)

The restricted and unrestricted runs gave the same results. Findings and the plan for the real feature are in
[Unsigned module UI spike: findings and plan](https://claude.ai/artifact/3x14faej48NQEfnHczyhbf).

With 10.0.14-embedded.2 (RemoteBlazorWebView net10 with PR #64), all three frames connect with no workarounds in the page.

- **open** and **locked** (opaque origin): the frame can't reach `window.top`, localStorage, cookies or popups. The locked relay needs `AllowOpaqueOrigin = true`.
- **samesrc:** the frame can't reach `window.top` or popups. localStorage is available, scoped to the relay's origin, and is shared by every module on the same relay.
- In every frame the shell can't read the frame's document.
- The module host's window must not be minimized: WebView2CompositionControl crashes creating its D3D9 device.
- The module page needs `<base href="/">`, which the relay rewrites to `/{id}/`.
