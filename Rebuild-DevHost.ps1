<#
.SYNOPSIS
  Clean-rebuild RemotePCDiagnostics.Host against the sibling RemoteBlazorWebView
  source (via RemotePCDiagnostics.Dev.sln), forcing the current
  remote.blazor.desktop.js bundle to be re-embedded, then verify it landed in the
  Host output.

.DESCRIPTION
  Visual Studio and a running RemotePCDiagnostics.Host both lock the output DLLs,
  which silently prevents a freshly built browser bundle from being copied into the
  app folder - so the app keeps running the old embedded JS even after a rebuild.
  This script stops the app, refuses to run while VS is open, deletes RemoteWebView's
  build outputs so the bundle is re-embedded, rebuilds the Host from the Dev solution
  (which flips UseRbwvSource -> ProjectReferences to the sibling RBWV source), and
  checks the result.

  Build the JS bundle FIRST in the RemoteBlazorWebView repo, with VS closed:
      .\RunTests.ps1 -Build:$true
  so dist\remote.blazor.desktop.js is current, then run this script.

.NOTES
  Expects RemoteBlazorWebView checked out beside this repo:
      ...\<parent>\RemoteBlazorWebView
      ...\<parent>\RemotePCDiagnostics   (this repo)
#>
[CmdletBinding()]
param(
  [string] $Configuration = 'Debug'
)

$rpcd = $PSScriptRoot
$rbwv = Join-Path (Split-Path $rpcd -Parent) 'RemoteBlazorWebView'

if (-not (Test-Path (Join-Path $rbwv 'src\RemoteWebView\RemoteWebView.csproj'))) {
  Write-Host "Sibling RemoteBlazorWebView repo not found at $rbwv - the source build needs it beside this repo." -ForegroundColor Red
  return
}

# 1) Stop the running app so its DLLs aren't locked.
Get-Process RemotePCDiagnostics.Host,RemotePCDiagnostics.ModuleHost -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Host "Stopping $($_.ProcessName) ($($_.Id))"; $_ | Stop-Process -Force }

# 2) Visual Studio locks the output DLLs too - refuse to build while it is open.
if (Get-Process devenv -ErrorAction SilentlyContinue) {
  Write-Host "Visual Studio is open - close it and re-run (it locks the build output)." -ForegroundColor Red
  return
}

# 3) Force the current JS bundle to be re-embedded into RemoteWebView.dll.
Remove-Item (Join-Path $rbwv 'src\RemoteWebView\bin'),(Join-Path $rbwv 'src\RemoteWebView\obj') -Recurse -Force -ErrorAction SilentlyContinue

# 4) Rebuild Host from the Dev solution (SolutionName flips UseRbwvSource -> source ProjectReferences).
Push-Location $rpcd
$log = dotnet build src\RemotePCDiagnostics.Host\RemotePCDiagnostics.Host.csproj -c $Configuration -p:SolutionName=RemotePCDiagnostics.Dev -t:Rebuild 2>&1
Pop-Location

# 5) Report locks / errors / success.
$locks = $log | Select-String 'MSB3061'
$errs  = $log | Select-String ': error '
if ($locks) {
  Write-Host "STILL LOCKED - a process is holding the output (close it and re-run):" -ForegroundColor Red
  $locks | Select-Object -First 5 | ForEach-Object { $_.Line.Trim() }
  return
}
if ($errs) {
  Write-Host "BUILD ERRORS:" -ForegroundColor Red
  $errs | ForEach-Object { $_.Line.Trim() }
  return
}
($log | Select-String 'Build succeeded') | ForEach-Object { Write-Host $_.Line -ForegroundColor Green }

# 6) Verify the Host output embeds the current bundle.
$js  = Get-Item (Join-Path $rbwv 'src\RemoteWebView.Blazor.JS\dist\remote.blazor.desktop.js')
$dll = Get-ChildItem -Recurse (Join-Path $rpcd 'src\RemotePCDiagnostics.Host\bin') -Filter RemoteWebView.dll -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $dll) {
  Write-Host "RemoteWebView.dll not found in Host output - the build may have failed." -ForegroundColor Red
  return
}
Write-Host ("host dll: {0}" -f $dll.LastWriteTime)
Write-Host ("bundle:   {0}" -f $js.LastWriteTime)
if ($dll.LastWriteTime -ge $js.LastWriteTime) {
  Write-Host "OK - Host embeds the current bundle. Launch the app, then open the technician /app link in a fresh Incognito window." -ForegroundColor Green
} else {
  Write-Host "WARNING - Host dll is older than the bundle; the embed did not refresh. Make sure the app and VS are closed, then re-run." -ForegroundColor Yellow
}
