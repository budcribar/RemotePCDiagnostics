using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// In-process Microsoft Defender WMI reader/writer (<c>root\Microsoft\Windows\Defender</c>),
/// replacing <c>DefenderExclusions.ps1</c> and <c>Add/Remove-MpPreference</c> PowerShell scripts.
/// </summary>
public static class WindowsDefenderWmi
{
    private const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    private const string StatusClass = "MSFT_MpComputerStatus";
    private const string PreferenceClass = "MSFT_MpPreference";

    /// <summary>
    /// Reads Defender real-time status, running mode, and exclusion lists as the JSON shape
    /// <see cref="Optimizations.DefenderProbe.Parse"/> expects. Returns null when Defender WMI is unavailable.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static string? ReadStatusJson()
    {
        var scope = new ManagementScope(DefenderNamespace);
        scope.Connect();

        var on = false;
        var mode = "";
        var gotAny = false;

        try
        {
            using var statusSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT RealTimeProtectionEnabled, AMServiceEnabled, AMRunningMode FROM " + StatusClass));
            using var statusResults = statusSearcher.Get();
            foreach (ManagementObject o in statusResults)
            {
                using (o)
                {
                    gotAny = true;
                    var rtp = o["RealTimeProtectionEnabled"] is bool b1 && b1;
                    var svc = o["AMServiceEnabled"] is bool b2 && b2;
                    on = rtp && svc;
                    mode = o["AMRunningMode"]?.ToString() ?? "";
                    break;
                }
            }
        }
        catch { }

        var (paths, procs, gotPref) = ReadExclusions(scope);
        if (!gotAny && !gotPref) return null;

        return JsonSerializer.Serialize(new
        {
            On = on ? "True" : "False",
            Mode = mode,
            Paths = paths,
            Procs = procs,
        });
    }

    /// <summary>
    /// Adds Defender folder and/or process exclusions via <c>MSFT_MpPreference.Add</c>, then reads back
    /// the current exclusions as JSON (<c>{"Paths":[...],"Procs":[...]}</c>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static string AddExclusions(IReadOnlyList<string> folders, IReadOnlyList<string> processes)
    {
        var scope = new ManagementScope(DefenderNamespace);
        scope.Connect();

        if (folders.Count > 0 || processes.Count > 0)
        {
            InvokePreferenceMethod(scope, "Add", p =>
            {
                if (folders.Count > 0) p["ExclusionPath"] = folders.ToArray();
                if (processes.Count > 0) p["ExclusionProcess"] = processes.ToArray();
            });
        }

        var (paths, procs, _) = ReadExclusions(scope);
        return JsonSerializer.Serialize(new { Paths = paths, Procs = procs });
    }

    /// <summary>Removes Defender folder and/or process exclusions via <c>MSFT_MpPreference.Remove</c>.</summary>
    [SupportedOSPlatform("windows")]
    public static void RemoveExclusions(IReadOnlyList<string> folders, IReadOnlyList<string> processes)
    {
        if (folders.Count == 0 && processes.Count == 0) return;

        var scope = new ManagementScope(DefenderNamespace);
        scope.Connect();

        InvokePreferenceMethod(scope, "Remove", p =>
        {
            if (folders.Count > 0) p["ExclusionPath"] = folders.ToArray();
            if (processes.Count > 0) p["ExclusionProcess"] = processes.ToArray();
        });
    }

    [SupportedOSPlatform("windows")]
    private static (List<string> Paths, List<string> Procs, bool Read) ReadExclusions(ManagementScope scope)
    {
        var paths = new List<string>();
        var procs = new List<string>();
        try
        {
            using var prefSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ExclusionPath, ExclusionProcess FROM " + PreferenceClass));
            using var prefResults = prefSearcher.Get();
            foreach (ManagementObject o in prefResults)
            {
                using (o)
                {
                    if (o["ExclusionPath"] is string[] ep)
                        paths.AddRange(ep.Where(s => !string.IsNullOrEmpty(s)));
                    if (o["ExclusionProcess"] is string[] epr)
                        procs.AddRange(epr.Where(s => !string.IsNullOrEmpty(s)));
                    return (paths, procs, true);
                }
            }
        }
        catch { }

        return (paths, procs, false);
    }

    [SupportedOSPlatform("windows")]
    private static void InvokePreferenceMethod(ManagementScope scope, string method, Action<ManagementBaseObject> fill)
    {
        using var cls = new ManagementClass(scope, new ManagementPath(PreferenceClass), null);
        using var input = cls.GetMethodParameters(method);
        fill(input);
        using var output = cls.InvokeMethod(method, input, null);
        var hr = output?["ReturnValue"] is { } rv ? Convert.ToUInt32(rv, CultureInfo.InvariantCulture) : 0u;
        if (hr != 0) throw new COMException($"Microsoft Defender refused {method} (0x{hr:X8}).", unchecked((int)hr));
    }
}
