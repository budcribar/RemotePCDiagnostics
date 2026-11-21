using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary><see cref="AgentScripts.WindowsUpdate"/>: finds every pending driver (or software) update, downloads and installs them.</summary>
public sealed record WindowsUpdateAction(bool DriversOnly) : AgentNativeAction;

/// <summary><see cref="AgentScripts.InstallUpdate"/>: installs the one update with this Windows Update ID.</summary>
public sealed record InstallUpdateAction(Guid UpdateId) : AgentNativeAction;

/// <summary>One update Windows Update found (<c>IUpdate</c>).</summary>
public interface IFoundUpdate
{
    string Title { get; }
    bool EulaAccepted { get; }
    void AcceptEula();
    bool IsDownloaded { get; }
}

/// <summary>What <c>IUpdateInstaller.Install</c> answered: <c>OperationResultCode</c> (2 succeeded, 3 with errors, 4 failed, 5 aborted).</summary>
public sealed record UpdateInstallOutcome(int ResultCode, int HResult, bool RebootRequired);

/// <summary>The Windows Update Agent calls the Agent makes (<see cref="WuaComApi"/> on Windows, a fake in tests).</summary>
public interface IWindowsUpdateApi
{
    IReadOnlyList<IFoundUpdate> Search(string criteria);
    /// <summary>Returns the download's <c>OperationResultCode</c>.</summary>
    int Download(IReadOnlyList<IFoundUpdate> updates);
    UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates);
    /// <summary>Asks Windows' own update client to scan (when nothing could be downloaded here).</summary>
    void StartInteractiveScan();
}

/// <summary>
/// The Windows Update changes the Agent makes for the app, in C# (they were the WindowsUpdate.ps1 and InstallUpdate.ps1 scripts).
/// The output is the JSON those scripts printed, so the app reads it the same way
/// (<see cref="Areas.RemediationService.ParseInstallUpdate"/> and the Windows Update fix).
/// </summary>
public static class AgentWindowsUpdate
{
    public const int SucceededCode = 2, SucceededWithErrorsCode = 3, FailedCode = 4;

    public static string Criteria(bool driversOnly) => driversOnly ? "IsInstalled=0 and Type='Driver'" : "IsInstalled=0 and Type='Software'";

    private static bool Succeeded(int code) => code is SucceededCode or SucceededWithErrorsCode;

    /// <summary>
    /// Every pending update of one kind. Exit 0 with <c>{Count, Installed, InstallResult, RebootRequired, Titles}</c>; exit 1 with the
    /// reason on stderr when Windows Update can't be searched (the script printed "0 updates" then, which read as "up to date").
    /// </summary>
    public static ProcessResult InstallAll(IWindowsUpdateApi api, bool driversOnly)
    {
        IReadOnlyList<IFoundUpdate> found;
        try { found = api.Search(Criteria(driversOnly)); }
        catch (Exception ex) when (ex is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            return new ProcessResult(1, "", "Windows Update couldn't search for updates: " + Describe(ex));
        }

        var titles = found.Select(u => u.Title).ToList();
        int installed = 0, installResult = -1, hresult = 0;
        var reboot = false;
        string? error = null;
        if (found.Count > 0)
        {
            try
            {
                foreach (var u in found)
                    if (!u.EulaAccepted) u.AcceptEula();
                api.Download(found);
            }
            catch (Exception ex) when (ex is COMException or InvalidOperationException or UnauthorizedAccessException)
            {
                // As before: what did download still installs, and nothing downloaded asks Windows to scan.
                error = "Download: " + Describe(ex);
            }

            var downloaded = found.Where(u => u.IsDownloaded).ToList();
            if (downloaded.Count > 0)
            {
                try
                {
                    var outcome = api.Install(downloaded);
                    (installResult, hresult, reboot) = (outcome.ResultCode, outcome.HResult, outcome.RebootRequired);
                    if (Succeeded(installResult)) installed = downloaded.Count;
                }
                catch (Exception ex) when (ex is COMException or InvalidOperationException or UnauthorizedAccessException)
                {
                    installResult = FailedCode;
                    hresult = ex.HResult;
                    error = Describe(ex);
                }
            }
            else
            {
                try { api.StartInteractiveScan(); } catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException) { }
            }
        }

        return new ProcessResult(0, Json(w =>
        {
            w.WriteNumber("Count", titles.Count);
            w.WriteNumber("Installed", installed);
            w.WriteNumber("InstallResult", installResult);
            w.WriteNumber("HResult", hresult);
            w.WriteBoolean("RebootRequired", reboot);
            w.WriteStartArray("Titles");
            foreach (var t in titles) w.WriteStringValue(t);
            w.WriteEndArray();
            if (error is not null) w.WriteString("Error", error);
        }), "");
    }

    /// <summary>
    /// One update by ID. Always exit 0 with <c>{Found, Installed, DownloadResult, ResultCode, HResult, RebootRequired, Title, Error}</c>,
    /// with Windows Update's own error in Error, as the script did.
    /// </summary>
    public static ProcessResult InstallOne(IWindowsUpdateApi api, Guid updateId)
    {
        bool found = false, installed = false, reboot = false;
        int downloadResult = -1, resultCode = -1, hresult = 0;
        string title = "", error = "";
        try
        {
            var r = api.Search($"IsInstalled=0 and UpdateID='{updateId:D}'");
            if (r.Count > 0)
            {
                var u = r[0];
                found = true;
                title = u.Title;
                if (!u.EulaAccepted) u.AcceptEula();
                IReadOnlyList<IFoundUpdate> one = [u];
                if (!u.IsDownloaded) downloadResult = api.Download(one);
                if (u.IsDownloaded)
                {
                    var outcome = api.Install(one);
                    (resultCode, hresult, reboot) = (outcome.ResultCode, outcome.HResult, outcome.RebootRequired);
                    installed = Succeeded(resultCode);
                }
            }
        }
        catch (Exception ex) when (ex is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            error = Describe(ex);
        }

        return new ProcessResult(0, Json(w =>
        {
            w.WriteBoolean("Found", found);
            w.WriteBoolean("Installed", installed);
            w.WriteNumber("DownloadResult", downloadResult);
            w.WriteNumber("ResultCode", resultCode);
            w.WriteNumber("HResult", hresult);
            w.WriteBoolean("RebootRequired", reboot);
            w.WriteString("Title", title);
            w.WriteString("Error", error);
        }), "");
    }

    /// <summary>The message with the HRESULT Windows Update gave (its codes, like 0x8024402C, are what people search for).</summary>
    public static string Describe(Exception ex)
    {
        var hex = $"0x{unchecked((uint)ex.HResult):X8}";
        var message = ex.Message.Trim();
        return message.Contains(hex, StringComparison.OrdinalIgnoreCase) ? message : $"{message} ({hex})";
    }

    private static string Json(Action<Utf8JsonWriter> body)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

/// <summary>The Windows Update Agent COM API (<c>Microsoft.Update.Session</c>: IUpdateSearcher, IUpdateDownloader, IUpdateInstaller).</summary>
[SupportedOSPlatform("windows")]
public sealed class WuaComApi : IWindowsUpdateApi, IDisposable
{
    private readonly dynamic _session;

    public WuaComApi()
    {
        _session = Create("Microsoft.Update.Session");
        try { _session.ClientApplicationID = "Remote PC Diagnostics"; } catch (COMException) { }
    }

    private static dynamic Create(string progId) =>
        Activator.CreateInstance(Type.GetTypeFromProgID(progId, throwOnError: true)!)
        ?? throw new InvalidOperationException($"Windows didn't create {progId}.");

    private sealed class Update(dynamic com) : IFoundUpdate
    {
        public dynamic Com { get; } = com;
        public string Title => (string?)Com.Title ?? "";
        public bool EulaAccepted => (bool)Com.EulaAccepted;
        public void AcceptEula() => Com.AcceptEula();
        public bool IsDownloaded => (bool)Com.IsDownloaded;
    }

    public IReadOnlyList<IFoundUpdate> Search(string criteria)
    {
        var searcher = _session.CreateUpdateSearcher();
        var result = searcher.Search(criteria);
        var updates = result.Updates;
        int count = updates.Count;
        var list = new List<IFoundUpdate>(count);
        for (var i = 0; i < count; i++) list.Add(new Update(updates.Item(i)));
        return list;
    }

    private static dynamic Collection(IReadOnlyList<IFoundUpdate> updates)
    {
        var c = Create("Microsoft.Update.UpdateColl");
        foreach (var u in updates) c.Add(((Update)u).Com);
        return c;
    }

    public int Download(IReadOnlyList<IFoundUpdate> updates)
    {
        var d = _session.CreateUpdateDownloader();
        d.Updates = Collection(updates);
        return (int)d.Download().ResultCode;
    }

    public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates)
    {
        var i = _session.CreateUpdateInstaller();
        i.Updates = Collection(updates);
        var r = i.Install();
        return new UpdateInstallOutcome((int)r.ResultCode, (int)r.HResult, (bool)r.RebootRequired);
    }

    public void StartInteractiveScan()
    {
        var uso = Path.Combine(Environment.SystemDirectory, "UsoClient.exe");
        using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uso, "StartInteractiveScan")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
    }

    public void Dispose()
    {
        try { Marshal.FinalReleaseComObject(_session); } catch (ArgumentException) { }
    }
}
