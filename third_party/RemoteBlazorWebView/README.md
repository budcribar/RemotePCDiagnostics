# RemoteBlazorWebView packages

These local NuGet packages are built from `budcribar/RemoteBlazorWebView` branch `net10` at `e95a3a1`
(which includes #74 mirror-safe remote component frames, #73 and #75 `RemoteComponentHostOptions.ExitWhenInputCloses`). Version `10.0.14-embedded.5` is a local
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
    dotnet build src/$p -c Release -p:Version=10.0.14-embedded.5
    dotnet pack src/$p -c Release --no-build -p:Version=10.0.14-embedded.5 -o <this folder>
}
```

Update `SHA256SUMS.txt` when replacing them. Replace this local build with a published package once available.
