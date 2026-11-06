# RemoteBlazorWebView packages

These local NuGet packages are built from `budcribar/RemoteBlazorWebView` branch `claude/remote-components-generator` at `011e7d8`
(net10 at `bd18a57` plus PR #69, remote components, and PR #70, their contract source generator; net10 already has the embedded relay,
scroll synchronization and PR #64, which lets pages in opaque-origin sandboxed iframes connect). Version `10.0.14-embedded.3` is a local
integration build, not a nuget.org release. The root `NuGet.Config` includes this directory so a fresh checkout and CI can
restore it. The version is set once, as `RbwvVersion` in the root `Directory.Build.props`.

Included packages, all under the upstream MIT license (https://github.com/budcribar/RemoteBlazorWebView):

- `PeakSWC.RemoteBlazorWebView.Wpf` and its `PeakSWC.RemoteWebView` dependency: the app's UI and the module UI host.
- `PeakSWC.RemoteWebViewService.Lib`: the relay inside the app that serves unsigned modules' UIs in Local mode.
- `PeakSWC.RemoteBlazorWebView.RemoteComponents`: remote components (the sandboxed frame, the stdin/stdout connection, and the source
  generator for `[RemoteComponentContract]`), used by `RemotePCDiagnostics.ModuleUi`; the WPF package's `RemoteComponentHost` runs the
  module UI host.

To reproduce, build the JS bundle in `src/RemoteWebView.Blazor.JS` (`npm run build:production`; see its `Build.md`), then from the
upstream repository root:

```powershell
foreach ($p in 'RemoteWebViewService.Lib', 'RemoteWebView', 'RemoteBlazorWebView.RemoteComponents', 'RemoteBlazorWebView.Wpf') {
    dotnet build src/$p -c Release -p:Version=10.0.14-embedded.3
    dotnet pack src/$p -c Release --no-build -p:Version=10.0.14-embedded.3 -o <this folder>
}
```

Update `SHA256SUMS.txt` when replacing them. Replace this local build with a published package once available.
