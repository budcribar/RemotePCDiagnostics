# RemoteBlazorWebView packages

These NuGet packages are built from the RemoteBlazorWebView `net10` branch (opt-in WPF voice + runtime control transfer).
Version `10.0.14-embedded.8` is a local integration build with opt-in WPF voice support. The root `NuGet.Config` includes this directory so a fresh checkout and CI can
restore it. The version is set once, as `RbwvVersion` in the root `Directory.Build.props`.

Included packages, all under the upstream MIT license (https://github.com/budcribar/RemoteBlazorWebView):

- `PeakSWC.RemoteBlazorWebView.Wpf` and its `PeakSWC.RemoteWebView` dependency: the app's UI and the module UI host.
- `PeakSWC.RemoteWebViewService.Lib`: the relay inside the app that serves unsigned modules' UIs in Local mode.
- `PeakSWC.RemoteBlazorWebView.RemoteComponents`: remote components (the sandboxed frame, the stdin/stdout connection, and the source
  generator for `[RemoteComponentContract]`), used by `RemotePCDiagnostics.ModuleUi`; the WPF package's `RemoteComponentHost` runs the
  module UI host.

To reproduce, build the JS bundle in `src/RemoteWebView.Blazor.JS` (`npm run build:production`; see its `Build.md`), then from the
upstream repository root with the RemoteBlazorWebViewTutorial checkout beside it:

```powershell
foreach ($p in 'RemoteWebViewService.Lib', 'RemoteWebView', 'RemoteBlazorWebView.RemoteComponents', 'RemoteBlazorWebView.Wpf') {
    dotnet pack src/$p -c Release -p:VersionSuffix=embedded.8 -p:GeneratePackageOnBuild=false -o <packages folder>
}
```

Update `SHA256SUMS.txt` when replacing them. Replace this local build with a published package once available.

## Voice relay

Deploy the RemoteWebViewService from the same branch before enabling `REMOTEPC_VOICE=1`. Serve the controller and host over HTTPS and forward WebSocket upgrades for `/voice/{id}/signal`, preserving the public Host header. Set `Voice__StunUrl` and, for connections that need a media relay, set `Voice__TurnUrl` and `Voice__TurnSecret` to a TURN service that supports shared-secret credentials.
