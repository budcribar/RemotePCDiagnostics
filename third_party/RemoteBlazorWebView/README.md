# RemoteBlazorWebView packages

These local NuGet packages are built from `budcribar/RemoteBlazorWebView` net10 at `514fb8d7` (the merge of PR #64, which lets pages in
opaque-origin sandboxed iframes connect; net10 already has the embedded relay and scroll synchronization). Version `10.0.14-embedded.2`
is a local integration build, not a nuget.org release. The root `NuGet.Config` includes this directory so a fresh checkout and CI can
restore it. The version is set once, as `RbwvVersion` in the root `Directory.Build.props`.

Included packages, all under the upstream MIT license (https://github.com/budcribar/RemoteBlazorWebView):

- `PeakSWC.RemoteBlazorWebView.Wpf` and its `PeakSWC.RemoteWebView` dependency: the app's UI and the module UI host.
- `PeakSWC.RemoteWebViewService.Lib`: the relay inside the app that serves unsigned modules' UIs in Local mode.

To reproduce, build the JS bundle in `src/RemoteWebView.Blazor.JS` (`npm run build:production`; see its `Build.md`), then from the
upstream repository root:

```powershell
foreach ($p in 'RemoteWebViewService.Lib', 'RemoteWebView', 'RemoteBlazorWebView.Wpf') {
    dotnet pack src/$p -c Release -p:Version=10.0.14-embedded.2 -o <this folder>
}
```

Update `SHA256SUMS.txt` when replacing them. Replace this local build with a published package once available.
