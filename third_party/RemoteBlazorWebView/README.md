# RemoteBlazorWebView scroll synchronization client

These local NuGet packages are built from `budcribar/RemoteBlazorWebView` net10 commit `052cee5c` (scroll synchronization cherry-picked from net11 `7578de00`). Version `10.0.14-scrollsync.1` is a local integration build, not a nuget.org release. The root `NuGet.Config` includes this directory so a fresh checkout and CI can restore it.

Included packages: `PeakSWC.RemoteBlazorWebView.Wpf` and its `PeakSWC.RemoteWebView` dependency. Both use the upstream MIT license. The upstream repository is https://github.com/budcribar/RemoteBlazorWebView.

To reproduce from that commit, run `npm ci` and `npm run build:noprotoc` in `src/RemoteWebView.Blazor.JS`, then run from the upstream repository root:

```powershell
dotnet build src/RemoteBlazorWebView.Wpf/RemoteBlazorWebView.Wpf.csproj -c Release -p:Platform=x64 -p:Version=10.0.14-scrollsync.1 -p:PackageVersion=10.0.14-scrollsync.1 -p:VersionPrefix=10.0.14 -p:VersionSuffix=scrollsync.1
```

The packages are produced in `artifacts`. Copy the two matching packages here and update `SHA256SUMS.txt` when replacing them. Replace this local build with a published package once available.
