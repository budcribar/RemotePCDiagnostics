# Network usage history prototype

Standalone experiment; not yet part of the service workflow or client report. Reads existing Windows history, not packet contents. Does not stop apps/services, disable startup, change network settings, or upload results.

## Run

Copy the self-contained `NetworkUsagePrototype.exe` to the laptop. No .NET installation is required for the published executable.

Double-click for the API-based seven-day report, or run:

```powershell
.\NetworkUsagePrototype.exe --days 7
```

Reports go into a new timestamped directory under **Documents\Remote PC Diagnostics\Network usage**. Open `network-usage.html`. The same directory includes raw CSV/JSON and `diagnostics.json` for troubleshooting. To choose a destination, add `--out C:\Temp\NetworkHistory` (prefer a new, empty folder).

If API access is denied or no attributed records are returned, open an **administrator terminal** and run:

```powershell
.\NetworkUsagePrototype.exe --srum --days 7
```

This mode uses the Windows `esentutl /y ... /vssrec sru ...` command to create a Volume Shadow Copy, recover transaction logs within that snapshot, and copy the recovered SRUM database into the report's `srum-work` directory. It reads only this copy. It never runs destructive database repair, stops the SRUM service, or opens the live database through ESE. Acquisition may take up to two minutes and can fail due to permissions, VSS restrictions, or schema differences. Failures produce an unavailable report with diagnostics; they do not imply zero traffic. The copied database is retained for troubleshooting and may contain other resource history, application paths, and user identities; keep it private and delete the report directory when no longer needed.

An existing database copy can be analyzed with `--srum-copy C:\Copies\SRUDB.dat`. The prototype makes another private working copy first; it does not recover a dirty input copy. Use `--demo --out C:\Temp\NetworkDemo` to inspect a clearly labeled synthetic sample without reading any machine history.

## Interpretation

- Reports rank the top 25 app identities or attribution buckets by total bytes and separate uploads from downloads. The CSV includes all returned records. Identical display names with different identities/users stay separate.
- Program labels use local executable product/description metadata when available, plus friendly names for recognized Windows app packages. Device paths are mapped to local drive paths for lookup. Original identities remain in the HTML and exports; missing-file fallbacks are marked as name unavailable. No remote file paths are read to resolve names.
- The requested period ends at the last completed UTC hour. This reduces trailing partial intervals but does not establish that every earlier record has been flushed or that the whole requested period is available.
- API mode reports each connection profile separately in raw records. API user attribution is unavailable. Some identities are shared/system buckets; no aggregate reconciliation is attempted in this prototype.
- SRUM mode retains user SIDs separately and displays raw interface LUIDs. It reads only the Network Data Usage provider table, not similarly named long-term tables, to avoid combining overlapping records. It reports observed record timestamps as context, not proof of continuous coverage or exact app execution times.
- Virtual adapters/VPNs and local transfers can complicate totals; do not present this as internet billing usage. No traffic rate or request-count claim is made.
- No reliable current-process or startup matching is attempted yet. Historical high volume alone does not authorize stopping an app or removing it from startup.
- Exit codes: `0` = records exported (or demo); `2` = report written but attributed history unavailable/empty; `1` = argument/output failure.

## Build and validation

```powershell
dotnet publish src/NetworkUsagePrototype/NetworkUsagePrototype.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/NetworkUsagePrototype
```

Tests cover aggregation, user/identity separation, HTML/CSV escaping, and reading/time-filtering a synthetic ESE database. Demo-mode smoke testing verifies the packaged executable and exports. Real API permissions, snapshot acquisition, and data agreement with Windows Settings still need a laptop run. The prototype is not a proven production SRUM collector.

Sources: [Microsoft SRUM guide, page 9](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf#page=9), [Windows attributed usage API and capability requirement](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.connectionprofile.getattributednetworkusageasync), [SRUM schema research](https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20%28SRUM%29.asciidoc), [Microsoft ManagedEsent](https://github.com/microsoft/ManagedEsent).
