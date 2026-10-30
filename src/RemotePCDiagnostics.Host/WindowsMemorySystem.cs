using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows probes and actions for memory suggestions. Per-user changes only (HKCU startup, the user's browser profile),
/// except service start-up type, which the user explicitly clicks and can undo. Nothing here runs without a UI click.
/// </summary>
public sealed class WindowsMemorySystem(OsqueryRunner? osquery, Action<string>? log = null) : IMemorySystem
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private void Log(string m) => log?.Invoke("[memory] " + m);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    public MemoryReading ReadMemory()
    {
        var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (!GlobalMemoryStatusEx(ref m)) throw new InvalidOperationException("GlobalMemoryStatusEx failed");
        return new((long)m.ullTotalPhys, (long)m.ullAvailPhys, (long)(m.ullTotalPageFile - m.ullAvailPageFile), (long)m.ullTotalPageFile);
    }

    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static string LocalStatePath(BrowserKind k) => Path.Combine(LocalAppData,
        k == BrowserKind.Chrome ? @"Google\Chrome\User Data\Local State" : @"Microsoft\Edge\User Data\Local State");

    private static readonly string[] SelfNames = [Process.GetCurrentProcess().ProcessName];

    public async Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> services, CancellationToken ct)
    {
        var mem = ReadMemory();

        // Service PIDs (osquery), so service-hosting processes are never offered as "Close app" and services get their process memory.
        var svcPid = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (osquery is not null)
        {
            var q = await osquery.RunQueryAsync("SELECT name, pid FROM services WHERE status = 'RUNNING' AND pid > 0;", ct).ConfigureAwait(false);
            if (q.Success) foreach (var r in q.Rows!) if (r.Int("pid") is int pid) svcPid[r.Str("name")] = pid;
        }
        var servicePids = svcPid.Values.ToHashSet();

        var procs = Process.GetProcesses();
        var byPid = new Dictionary<int, long>();
        var groups = new Dictionary<string, (int n, long bytes, bool win, bool svc, DateTime? start)>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in procs)
        {
            try
            {
                if (p.Id <= 4) continue;
                var ws = p.WorkingSet64;
                byPid[p.Id] = ws;
                bool win = false; DateTime? start = null;
                try { win = p.MainWindowHandle != IntPtr.Zero; } catch { }
                try { start = p.StartTime; } catch { }
                var name = p.ProcessName;
                groups.TryGetValue(name, out var g);
                groups[name] = (g.n + 1, g.bytes + ws, g.win || win, g.svc || servicePids.Contains(p.Id),
                    g.start is null ? start : start is null ? g.start : (start < g.start ? start : g.start));
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            finally { p.Dispose(); }
        }
        var apps = groups.Select(kv => new AppUsage(kv.Key, kv.Value.n, kv.Value.bytes, kv.Value.win && !SelfNames.Contains(kv.Key, StringComparer.OrdinalIgnoreCase), kv.Value.svc,
            kv.Value.start is { } st ? DateTime.Now - st : null)).ToList();

        var pidCounts = svcPid.Values.GroupBy(v => v).ToDictionary(g => g.Key, g => g.Count());
        var svcUsage = services.Where(s => s.IsRunning).Select(s =>
            svcPid.TryGetValue(s.Name, out var pid) ? new ServiceUsage(s, byPid.TryGetValue(pid, out var b) ? b : null, pidCounts[pid]) : new ServiceUsage(s, null)).ToList();

        var browsers = new List<BrowserInfo>();
        foreach (var k in new[] { BrowserKind.Chrome, BrowserKind.Edge })
        {
            var path = LocalStatePath(k);
            if (!File.Exists(path)) continue;
            string? json = null;
            try { json = await File.ReadAllTextAsync(path, ct).ConfigureAwait(false); } catch (IOException ex) { Log($"Read {k} Local State failed: {ex.Message}"); }
            browsers.Add(new(k, true, IsBrowserRunning(k), BrowserPrefs.ReadMemorySaver(json, k), json is not null && BrowserPrefs.EnableMemorySaver(json, k) is not null));
        }

        return new(mem, apps, TimeSpan.FromMilliseconds(Environment.TickCount64), ReadFastStartup(), browsers, ReadVisualStudio(), ReadStartup(), svcUsage, ReadDevices());
    }

    private bool? ReadFastStartup()
    {
        try { return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", null) is int v ? v == 1 : null; }
        catch (Exception ex) { Log("Fast Startup read failed: " + ex.Message); return null; }
    }

    private VisualStudioInfo? ReadVisualStudio()
    {
        try
        {
            var exts = new List<VsExtension>();
            var root = Path.Combine(LocalAppData, @"Microsoft\VisualStudio");
            var liveShare = false;
            if (Directory.Exists(root))
                foreach (var inst in Directory.EnumerateDirectories(root))
                {
                    var extDir = Path.Combine(inst, "Extensions");
                    if (!Directory.Exists(extDir)) continue;
                    foreach (var manifest in Directory.EnumerateFiles(extDir, "extension.vsixmanifest", SearchOption.AllDirectories))
                    {
                        var dir = Path.GetDirectoryName(manifest)!;
                        var name = ManifestName(manifest) ?? Path.GetFileName(dir);
                        if (name.Contains("Live Share", StringComparison.OrdinalIgnoreCase)) liveShare = true;
                        long size = 0;
                        try { size = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length); } catch (IOException) { }
                        exts.Add(new(name, size));
                    }
                }
            foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
            {
                var vsRoot = Path.Combine(pf, "Microsoft Visual Studio");
                if (!Directory.Exists(vsRoot)) continue;
                foreach (var ide in Directory.EnumerateDirectories(vsRoot, "IDE", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 4, IgnoreInaccessible = true }))
                    if (Directory.Exists(Path.Combine(ide, @"Extensions\Microsoft\LiveShare"))) liveShare = true;
            }
            var deduped = exts
                .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(x => x.SizeBytes).First())
                .ToList();
            return new(liveShare, deduped);
        }
        catch (Exception ex) { Log("Visual Studio probe failed: " + ex.Message); return null; }
    }

    private static string? ManifestName(string path)
    {
        try { return XDocument.Load(path).Descendants().FirstOrDefault(e => e.Name.LocalName == "DisplayName")?.Value.Trim(); }
        catch (Exception) { return null; }
    }

    private List<StartupEntry> ReadStartup()
    {
        var list = new List<StartupEntry>();
        try
        {
            using var run = Registry.CurrentUser.OpenSubKey(RunKey);
            if (run is null) return list;
            foreach (var n in run.GetValueNames())
                if (run.GetValue(n) is string cmd) list.Add(new(n, cmd, StartupParsing.IsEnabled(GetStartupApproved(n))));
        }
        catch (Exception ex) { Log("Startup read failed: " + ex.Message); }
        return list;
    }

    private DeviceFacts ReadDevices()
    {
        bool? printer = null, bt = null, bio = null;
        try
        {
            using var p = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Print\Printers");
            if (p is not null) printer = p.GetSubKeyNames().Any(n => !n.Contains("PDF", StringComparison.OrdinalIgnoreCase) && !n.Contains("XPS", StringComparison.OrdinalIgnoreCase)
                && !n.Contains("OneNote", StringComparison.OrdinalIgnoreCase) && !n.Equals("Fax", StringComparison.OrdinalIgnoreCase));
            using var b = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
            bt = b is not null && b.SubKeyCount > 0;
            using var f = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{53D29EF7-377C-4D14-864B-EB3A85769359}");
            bio = f is not null && f.GetSubKeyNames().Any(n => int.TryParse(n, out _));
        }
        catch (Exception ex) { Log("Device probe failed: " + ex.Message); }
        return new(printer, bt, bio);
    }

    public async Task<ActionOutcome> CloseAppAsync(string processName, CancellationToken ct)
    {
        var procs = Process.GetProcessesByName(processName);
        var asked = 0;
        foreach (var p in procs) { try { if (p.MainWindowHandle != IntPtr.Zero && p.CloseMainWindow()) asked++; } catch (InvalidOperationException) { } }
        if (asked == 0) { Dispose(procs); return new(false, $"{MemoryText.FriendlyAppName(processName)} has no window to close. Close it yourself, or use Force close."); }
        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (DateTime.UtcNow < deadline && procs.Any(p => { try { return !p.HasExited && p.MainWindowHandle != IntPtr.Zero; } catch { return false; } }))
            await Task.Delay(250, ct).ConfigureAwait(false);
        var stillOpen = procs.Count(p => { try { p.Refresh(); return !p.HasExited && p.MainWindowHandle != IntPtr.Zero; } catch { return false; } });
        Dispose(procs);
        Log($"Close '{processName}': asked {asked} window(s), {stillOpen} still open");
        return stillOpen == 0
            ? new(true, $"Closed {MemoryText.FriendlyAppName(processName)}.")
            : new(false, $"{MemoryText.FriendlyAppName(processName)} didn't close (it may be asking to save). Check its window, or use Force close.");
    }

    public async Task<ActionOutcome> ForceCloseAppAsync(string processName, CancellationToken ct)
    {
        var procs = Process.GetProcessesByName(processName);
        foreach (var p in procs) { try { p.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { Log($"Kill {processName}/{p.Id}: {ex.Message}"); } }
        await Task.Delay(500, ct).ConfigureAwait(false);
        Dispose(procs);
        var left = Process.GetProcessesByName(processName); var n = left.Length; Dispose(left);
        return n == 0 ? new(true, $"Ended {MemoryText.FriendlyAppName(processName)}.") : new(false, $"Couldn't end every {MemoryText.FriendlyAppName(processName)} process.");
    }

    private static void Dispose(Process[] ps) { foreach (var p in ps) p.Dispose(); }

    public async Task<ActionOutcome> RunCommandAsync(string fileName, IReadOnlyList<string> args, CancellationToken ct)
    {
        if (!MemoryCommandAllowlist.IsAllowed(fileName, args)) return new(false, "Not allowed.");
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var output = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            Log($"{fileName} {string.Join(' ', args)} exit={p.ExitCode} out={output.Trim()}");
            return p.ExitCode == 0 ? new(true, "Build servers shut down (they start again on your next build).") : new(false, "The build servers didn't shut down.");
        }
        catch (System.ComponentModel.Win32Exception ex) { Log("dotnet not found: " + ex.Message); return new(false, "The .NET SDK (dotnet) wasn't found on this PC."); }
    }

    public byte[]? GetStartupApproved(string name)
    {
        using var k = Registry.CurrentUser.OpenSubKey(ApprovedKey);
        return k?.GetValue(name) as byte[];
    }

    public void SetStartupApproved(string name, byte[]? value)
    {
        using var run = Registry.CurrentUser.OpenSubKey(RunKey);
        if (run?.GetValue(name) is null) throw new InvalidOperationException("Not a per-user startup entry");
        using var k = Registry.CurrentUser.CreateSubKey(ApprovedKey);
        if (value is null) k.DeleteValue(name, throwOnMissingValue: false);
        else k.SetValue(name, value, RegistryValueKind.Binary);
    }

    public bool IsBrowserRunning(BrowserKind kind)
    {
        var ps = Process.GetProcessesByName(BrowserPrefs.ProcessName(kind));
        var any = ps.Length > 0; Dispose(ps); return any;
    }

    public string? ReadBrowserLocalState(BrowserKind kind) { var p = LocalStatePath(kind); return File.Exists(p) ? File.ReadAllText(p) : null; }

    public void WriteBrowserLocalState(BrowserKind kind, string json)
    {
        if (IsBrowserRunning(kind)) throw new InvalidOperationException("Browser is running");
        var path = LocalStatePath(kind);
        var tmp = path + ".rpd-tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }

    public void OpenUri(string uri)
    {
        if (!MemoryCommandAllowlist.IsAllowedSettingsUri(uri)) throw new InvalidOperationException("Not allowed");
        if (uri.StartsWith("chrome://", StringComparison.OrdinalIgnoreCase)) { Process.Start(new ProcessStartInfo("chrome.exe", uri) { UseShellExecute = true })?.Dispose(); return; }
        if (uri.StartsWith("edge://", StringComparison.OrdinalIgnoreCase)) { Process.Start(new ProcessStartInfo("msedge.exe", uri) { UseShellExecute = true })?.Dispose(); return; }
        Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true })?.Dispose();
    }

    private static string ServiceKey(string name) => @"SYSTEM\CurrentControlSet\Services\" + name;

    public string GetServiceStartType(string name)
    {
        using var k = Registry.LocalMachine.OpenSubKey(ServiceKey(name)) ?? throw new InvalidOperationException("Service not found");
        var start = k.GetValue("Start") as int? ?? 3;
        var delayed = k.GetValue("DelayedAutostart") as int? == 1;
        return start switch { 2 => delayed ? "AutomaticDelayed" : "Automatic", 4 => "Disabled", _ => "Manual" };
    }

    public void SetServiceStartType(string name, string startType)
    {
        if (!MemorySuggestionService.StartTypes.Contains(startType)) throw new ArgumentException("Bad start type");
        if (ServiceProtection.IsProtected(name) || ServiceProtection.IsSelfComponent(name)) throw new InvalidOperationException("Protected");
        using var k = Registry.LocalMachine.OpenSubKey(ServiceKey(name), writable: true) ?? throw new InvalidOperationException("Service not found");
        k.SetValue("Start", startType switch { "Automatic" or "AutomaticDelayed" => 2, "Disabled" => 4, _ => 3 }, RegistryValueKind.DWord);
        if (startType == "AutomaticDelayed") k.SetValue("DelayedAutostart", 1, RegistryValueKind.DWord);
        else if (startType == "Automatic") k.SetValue("DelayedAutostart", 0, RegistryValueKind.DWord);
        Log($"Service '{name}' start type set to {startType}");
    }
}
