using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Projects;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows probes and actions for memory suggestions. Per-user changes only (HKCU startup, the user's browser profile),
/// except service start-up type, which the user explicitly clicks and can undo. Nothing here runs without a UI click.
/// </summary>
public sealed partial class WindowsMemorySystem(OsqueryRunner? osquery, Action<string>? log = null) : IMemorySystem
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Run32Key = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string Approved32Key = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    private const string UwpStartupKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
    private const int SM_DIGITIZER = 94;
    private const int NID_INTEGRATED_PEN = 0x04, NID_EXTERNAL_PEN = 0x08;
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int nIndex);
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
            svcPid.TryGetValue(s.Name, out var pid) ? new ServiceUsage(s, byPid.TryGetValue(pid, out var b) ? b : null, pidCounts[pid]) : new ServiceUsage(s, null))
            .Select(u => AiVmServices.Is(u.Info.Name) ? u with { UsersCanStart = ReadUsersCanStart(u.Info.Name) } : u).ToList();

        var browsers = new List<BrowserInfo>();
        var backgrounds = new List<BrowserBackgroundInfo>();
        foreach (var k in new[] { BrowserKind.Chrome, BrowserKind.Edge })
        {
            var path = LocalStatePath(k);
            if (!File.Exists(path)) continue;
            string? json = null;
            try { json = await File.ReadAllTextAsync(path, ct).ConfigureAwait(false); } catch (IOException ex) { Log($"Read {k} Local State failed: {ex.Message}"); }
            browsers.Add(new(k, true, IsBrowserRunning(k), BrowserPrefs.ReadMemorySaver(json, k), json is not null && BrowserPrefs.EnableMemorySaver(json, k) is not null));
            backgrounds.Add(ReadBrowserBackground(k, json));
        }

        var probe = await RunPowerShellAsync(MemoryProbe.Script, ct).ConfigureAwait(false);
        var (autoPageFile, slots) = MemoryProbe.Parse(probe.ExitCode == 0 ? probe.Output : null);
        var defender = apps.Any(a => a.Name.Equals("MsMpEng", StringComparison.OrdinalIgnoreCase)) ? await ReadDefenderAsync(ct).ConfigureAwait(false) : null;
        return new(mem, apps, TimeSpan.FromMilliseconds(Environment.TickCount64), ReadFastStartup(), browsers, ReadVisualStudio(), ReadStartup(), svcUsage, ReadDevices(),
            GetTransparency(), autoPageFile, slots, ReadDefaultBrowser(), defender, ReadFeeds(), ReadHibernate(), ReadOfficeStart(), ReadDefaultPrinter(), ReadOfficePrivacy(), ReadExtensions(ct), backgrounds, ReadRemovableApps());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

    /// <summary>Hibernation type, custom size, hiberfil.sys size, Fast Startup and whether the PC has a battery. Null = couldn't read.</summary>
    public HibernateInfo? ReadHibernate()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(Hibernation.PowerKey);
            if (k is null) return null;
            var path = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:", "hiberfil.sys");
            long? bytes = null;
            try { var fi = new FileInfo(path); if (fi.Exists) bytes = fi.Length; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            var enabled = k.GetValue("HibernateEnabled") is int e ? e != 0 && bytes is > 0 : bytes is > 0;
            bool? battery = null;
            try { if (GetSystemPowerStatus(out var ps)) battery = ps.BatteryFlag switch { 128 => false, 255 => null, _ => true }; } catch (Exception ex) { Log("power status: " + ex.Message); }
            return new(enabled, Hibernation.IsReduced(k.GetValue("HiberFileType") as int?, bytes, ReadMemory().TotalBytes),
                Hibernation.IsCustomSize(k.GetValue("HiberFileSizePercent") as int?), bytes, ReadFastStartup(), battery);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Log("Hibernation read failed: " + ex.Message); return null; }
    }

    /// <summary>Only ever runs System32\powercfg.exe /h /type reduced|full.</summary>
    public async Task<ActionOutcome> SetHibernateTypeAsync(bool reduced, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "powercfg.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "/h", "/type", reduced ? "reduced" : "full" }) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(60));
            var err = p.StandardError.ReadToEndAsync(timeout.Token);
            var output = p.StandardOutput.ReadToEndAsync(timeout.Token);
            await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (p.ExitCode == 0) return new(true, reduced ? "Hibernation file reduced." : "Hibernation file full size.");
            Log($"powercfg /h /type failed ({p.ExitCode}): {(await err.ConfigureAwait(false)).Trim()} {(await output.ConfigureAwait(false)).Trim()}");
            return new(false, "Windows didn't allow changing the hibernation file (a custom size may be set, or administrator rights are missing).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            Log("powercfg failed: " + ex.Message);
            return new(false, "Couldn't run powercfg.");
        }
    }

    private const string PackagesKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    private const string WidgetsPackage = "MicrosoftWindows.Client.WebExperience_";

    /// <summary>Widgets / Search highlights state: registry reads only. Null when it couldn't be read (nothing is offered then).</summary>
    private WindowsFeedsInfo? ReadFeeds()
    {
        try
        {
            bool installed = false;
            using (var pk = Registry.CurrentUser.OpenSubKey(PackagesKey))
                installed = pk?.GetSubKeyNames().Any(n => n.StartsWith(WidgetsPackage, StringComparison.OrdinalIgnoreCase)) == true;
            int? taskbarDa = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", null) as int?;
            return new(Environment.OSVersion.Version.Build, ReadDword(RegistryAllowlist.WidgetsPolicy), installed, taskbarDa,
                ReadDword(RegistryAllowlist.SearchHighlightsPolicy), ReadDword(RegistryAllowlist.SearchHighlightsToggle));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Widgets/Search highlights read failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// #23: the installed Office 16.x apps (Word, Excel, PowerPoint) and this account's start screen setting, from the registry only.
    /// An app counts as installed when its App Paths entry points into an Office16 folder, its MSI 16.0 InstallRoot is set, or a
    /// 16.x Click-to-Run product includes it (64- and 32-bit views). Null = couldn't read (nothing is offered then).
    /// </summary>
    private OfficeStartInfo? ReadOfficeStart()
    {
        try
        {
            var apps = new List<OfficeStartApp>();
            foreach (var app in OfficeStartScreen.AppNames)
            {
                if (!IsOffice16AppInstalled(app) || OfficeStartScreen.Setting(app) is not { } setting) continue;
                try { apps.Add(new(app, ReadDword(setting))); }
                catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.Security.SecurityException or IOException)
                { Log($"{app} start screen setting read failed: {ex.Message}"); } // not a DWORD or unreadable: leave this app alone
            }
            return new(apps);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Office start screen read failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// #18: whether Office 16.x (Word, Excel or PowerPoint) is installed, and this account's Office privacy policy values, from the registry only.
    /// DisconnectedState is only read here (it's not on the allowlist). Null = couldn't read or not DWORDs (nothing is offered then).
    /// </summary>
    private OfficePrivacyInfo? ReadOfficePrivacy()
    {
        try
        {
            var installed = OfficeStartScreen.AppNames.Any(IsOffice16AppInstalled);
            if (!installed) return new(false, null, null);
            int? disconnected = null;
            using (var k = Registry.CurrentUser.OpenSubKey(OfficePrivacy.PolicyKey))
                if (k?.GetValue(OfficePrivacy.DisconnectedStateName) is { } v)
                {
                    if (k.GetValueKind(OfficePrivacy.DisconnectedStateName) != RegistryValueKind.DWord || v is not int i) return null;
                    disconnected = i;
                }
            return new(true, ReadDword(OfficePrivacy.Setting), disconnected);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Office privacy policy read failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// #19: background_mode.enabled from the Local State JSON already read for the memory saver card, the BackgroundModeEnabled policy
    /// (HKLM, else HKCU) and, for Edge, the StartupBoostEnabled policy in HKLM and HKCU. Registry reads only.
    /// </summary>
    private BrowserBackgroundInfo ReadBrowserBackground(BrowserKind kind, string? localState)
    {
        var ok = BrowserBackground.TryReadBackgroundMode(localState, out var pref);
        var policyKey = kind == BrowserKind.Chrome ? @"SOFTWARE\Policies\Google\Chrome" : @"SOFTWARE\Policies\Microsoft\Edge";
        var bgPolicy = PolicyDword(Registry.LocalMachine, policyKey, "BackgroundModeEnabled") ?? PolicyDword(Registry.CurrentUser, policyKey, "BackgroundModeEnabled");
        int? boostLm = null, boostCu = null;
        if (kind == BrowserKind.Edge)
        {
            boostLm = PolicyDword(Registry.LocalMachine, policyKey, "StartupBoostEnabled");
            boostCu = PolicyDword(Registry.CurrentUser, policyKey, "StartupBoostEnabled");
        }
        return new(kind, ok, pref, bgPolicy, boostLm, boostCu);
    }

    /// <summary>A browser policy value (read only). A value that exists but isn't a DWORD, or can't be read, counts as set (-1), so nothing is changed.</summary>
    private int? PolicyDword(RegistryKey root, string key, string name)
    {
        try
        {
            using var k = root.OpenSubKey(key);
            if (k?.GetValue(name) is not { } v) return null;
            return k.GetValueKind(name) == RegistryValueKind.DWord && v is int i ? i : -1;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        { Log($"Read {key}\\{name} failed: {ex.Message}"); return -1; }
    }

    private static bool IsOffice16AppInstalled(string app)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using (var appPath = hklm.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{OfficeStartScreen.Exe(app)}"))
                if (OfficeStartScreen.IsOffice16Path(appPath?.GetValue(null) as string ?? appPath?.GetValue("Path") as string)) return true;
            using (var msi = hklm.OpenSubKey($@"SOFTWARE\Microsoft\Office\16.0\{app}\InstallRoot"))
                if (msi?.GetValue("Path") is string p && p.Length > 0) return true;
            using var c2r = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Office\ClickToRun\Configuration");
            if (c2r is not null && OfficeStartScreen.IsOffice16Version(c2r.GetValue("VersionToReport") as string)
                && OfficeStartScreen.InClickToRun(app, c2r.GetValue("ProductReleaseIds") as string, id => c2r.GetValue(id + ".ExcludedApps") as string))
                return true;
        }
        return false;
    }

    [DllImport("winspool.drv", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetDefaultPrinterW")]
    private static extern bool SetDefaultPrinterNative(string pszPrinter);

    /// <summary>
    /// #24: this account's default printer (HKCU ...\Windows NT\CurrentVersion\Windows\Device = "name,winspool,port"), its real port from
    /// HKLM ...\Print\Printers\&lt;name&gt;\Port (the Device value's port is a placeholder like "Ne01:"), LegacyDefaultPrinterMode, and whether
    /// Microsoft Print to PDF is installed. Registry only. Null = couldn't read (nothing is offered then).
    /// </summary>
    public DefaultPrinterInfo? ReadDefaultPrinter()
    {
        try
        {
            using var w = Registry.CurrentUser.OpenSubKey(DefaultPrinter.WindowsKey);
            var name = DefaultPrinter.ParseDevice(w?.GetValue("Device") as string);
            int? mode = null;
            try { mode = ReadDword(RegistryAllowlist.LegacyDefaultPrinterMode); }
            catch (InvalidOperationException ex) { Log("LegacyDefaultPrinterMode: " + ex.Message); return null; } // not a DWORD: leave it alone
            using var printers = Registry.LocalMachine.OpenSubKey(DefaultPrinter.PrintersKey);
            string? port = null;
            if (name is not null && !name.Contains('\\') && printers is not null)
            {
                using var pk = printers.OpenSubKey(name);
                port = pk?.GetValue("Port") as string;
            }
            bool pdf;
            using (var pdfKey = printers?.OpenSubKey(DefaultPrinter.PdfPrinter)) pdf = pdfKey is not null;
            return new(name, port, mode, pdf);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Default printer read failed: " + ex.Message); return null; }
    }

    /// <summary>An installed local printer (HKLM Print\Printers subkey) or a \\server\printer connection (HKCU Printers\Connections). Only safe names.</summary>
    public bool PrinterExists(string name)
    {
        if (!DefaultPrinter.IsSafeName(name)) return false;
        if (DefaultPrinter.IsConnectionName(name))
        {
            using var c = Registry.CurrentUser.OpenSubKey(DefaultPrinter.ConnectionsKey);
            if (c?.GetSubKeyNames().Any(n => n.Equals(DefaultPrinter.ConnectionKeyName(name), StringComparison.OrdinalIgnoreCase)) == true) return true;
        }
        using var p = Registry.LocalMachine.OpenSubKey(DefaultPrinter.PrintersKey);
        return p?.GetSubKeyNames().Any(n => n.Equals(name, StringComparison.OrdinalIgnoreCase)) == true;
    }

    /// <summary>winspool SetDefaultPrinter for this account, only for an installed printer with a safe name (Microsoft Print to PDF, or the journaled previous default).</summary>
    public ActionOutcome SetDefaultPrinter(string name)
    {
        if (!PrinterExists(name)) return new(false, $"\"{name}\" isn't installed on this PC.");
        if (SetDefaultPrinterNative(name)) { Log($"Default printer set to {name}"); return new(true, $"{name} is the default printer."); }
        Log($"SetDefaultPrinter({name}) failed: Win32 error {Marshal.GetLastWin32Error()}");
        return new(false, "Windows didn't allow changing the default printer.");
    }

    private static string UserDataDir(BrowserKind k) => Path.Combine(LocalAppData, k == BrowserKind.Chrome ? @"Google\Chrome\User Data" : @"Microsoft\Edge\User Data");

    /// <summary>Reads a profile file the browser may have open (it replaces files atomically, so sharing is enough). Null = unreadable.</summary>
    private string? ReadShared(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var r = new StreamReader(fs);
            return r.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log($"Read {path} failed: {ex.Message}"); return null; }
    }

    private static long FolderBytes(string path)
    {
        long sum = 0;
        foreach (var f in Directory.EnumerateFiles(path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
            try { sum += new FileInfo(f).Length; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return sum;
    }

    /// <summary>
    /// #22: allowlisted extensions installed in any Chrome / Edge profile of this account (folders with a Preferences file:
    /// Default, Profile 1, …), plus both machine blocklists. File reads only. An extension counts when its
    /// <c>Extensions\&lt;id&gt;\&lt;version&gt;</c> folder exists and, when the profile's (Secure) Preferences lists extensions,
    /// it's registered there too (a leftover folder after an uninstall doesn't count). Null = couldn't read.
    /// </summary>
    private BrowserExtensionsInfo? ReadExtensions(CancellationToken ct)
    {
        try
        {
            var found = new List<FoundExtension>();
            foreach (var k in new[] { BrowserKind.Chrome, BrowserKind.Edge })
            {
                var userData = UserDataDir(k);
                if (!Directory.Exists(userData)) continue;
                var names = BrowserExtensions.ProfileNames(ReadShared(Path.Combine(userData, "Local State")));
                var byId = new Dictionary<string, (List<string> Profiles, long Bytes)>(StringComparer.OrdinalIgnoreCase);
                foreach (var dir in Directory.EnumerateDirectories(userData))
                {
                    ct.ThrowIfCancellationRequested();
                    if (!File.Exists(Path.Combine(dir, "Preferences"))) continue;
                    var known = BrowserExtensions.KnownFor(k).Where(e => HasVersionFolder(Path.Combine(dir, "Extensions", e.Id))).ToList();
                    if (known.Count == 0) continue;
                    var registered = BrowserExtensions.IdsInPreferences(ReadShared(Path.Combine(dir, "Secure Preferences")), ReadShared(Path.Combine(dir, "Preferences")));
                    var folder = Path.GetFileName(dir);
                    foreach (var e in known)
                    {
                        if (registered is not null && !registered.Contains(e.Id)) continue;
                        if (!byId.TryGetValue(e.Id, out var acc)) acc = ([], 0);
                        acc.Profiles.Add(names.GetValueOrDefault(folder, folder));
                        try { acc.Bytes += FolderBytes(Path.Combine(dir, "Extensions", e.Id)); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                        byId[e.Id] = acc;
                    }
                }
                found.AddRange(byId.Select(kv => new FoundExtension(k, kv.Key, kv.Value.Profiles, kv.Value.Bytes > 0 ? kv.Value.Bytes : null)));
            }
            return new(found, SafeBlocklist(BrowserKind.Chrome), SafeBlocklist(BrowserKind.Edge));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Browser extensions read failed: " + ex.Message); return null; }
    }

    private static bool HasVersionFolder(string extensionDir)
    {
        try { return Directory.Exists(extensionDir) && Directory.EnumerateDirectories(extensionDir).Any(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private IReadOnlyList<BlocklistEntry>? SafeBlocklist(BrowserKind k)
    {
        try { return ReadExtensionBlocklist(k); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log($"{k} extension blocklist read failed: {ex.Message}"); return null; }
    }

    private static RegistryKey Hklm64() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    public IReadOnlyList<BlocklistEntry>? ReadExtensionBlocklist(BrowserKind browser)
    {
        using var hklm = Hklm64();
        using var key = hklm.OpenSubKey(BrowserExtensions.BlocklistKey(browser));
        if (key is null) return [];
        return key.GetValueNames().Select(n => new BlocklistEntry(n, key.GetValueKind(n) == RegistryValueKind.String ? key.GetValue(n) as string : null)).ToList();
    }

    /// <summary>Only allowlisted IDs, only as a new numbered value; never overwrites an existing value.</summary>
    public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId)
    {
        if (BrowserExtensions.Known(browser, extensionId) is not { } known) throw new InvalidOperationException($"{extensionId} isn't an extension this app may block.");
        if (!BrowserExtensions.IsEntryName(valueName)) throw new InvalidOperationException($"'{valueName}' isn't a blocklist entry name.");
        using var hklm = Hklm64();
        using var key = hklm.CreateSubKey(BrowserExtensions.BlocklistKey(browser), writable: true) ?? throw new UnauthorizedAccessException("Can't open the blocklist key.");
        if (key.GetValue(valueName) is not null) throw new InvalidOperationException($"Blocklist entry {valueName} already exists.");
        key.SetValue(valueName, known.Id, RegistryValueKind.String);
        Log($"HKLM\\{BrowserExtensions.BlocklistKey(browser)}\\{valueName} = {known.Id} ({known.Name})");
    }

    /// <summary>Deletes the value only while it still holds this allowlisted ID; other entries are never touched or renumbered.</summary>
    public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId)
    {
        if (BrowserExtensions.Known(browser, extensionId) is not { } known) throw new InvalidOperationException($"{extensionId} isn't an extension this app may block.");
        if (!BrowserExtensions.IsEntryName(valueName)) throw new InvalidOperationException($"'{valueName}' isn't a blocklist entry name.");
        using var hklm = Hklm64();
        using var key = hklm.OpenSubKey(BrowserExtensions.BlocklistKey(browser), writable: true);
        if (key?.GetValue(valueName) is not string data || !data.Trim().Equals(known.Id, StringComparison.OrdinalIgnoreCase)) return;
        key.DeleteValue(valueName, throwOnMissingValue: false);
        Log($"HKLM\\{BrowserExtensions.BlocklistKey(browser)}\\{valueName} ({known.Name}) deleted");
    }

    /// <summary>Only values on <see cref="RegistryAllowlist"/>; the allowlisted entry's own key and name are used, never the caller's.</summary>
    private static RegistrySetting Allowed(RegistrySetting setting) =>
        RegistryAllowlist.Find(setting.Target) ?? throw new InvalidOperationException($"{setting.Target} isn't a registry value this app may change.");

    private static RegistryKey OpenBase(RegistrySetting s) => RegistryKey.OpenBaseKey(
        s.Root == RegistryRoot.LocalMachine ? Microsoft.Win32.RegistryHive.LocalMachine : Microsoft.Win32.RegistryHive.CurrentUser, RegistryView.Registry64);

    public int? ReadDword(RegistrySetting setting)
    {
        var s = Allowed(setting);
        using var root = OpenBase(s);
        using var k = root.OpenSubKey(s.Key);
        if (k?.GetValue(s.Name) is not { } v) return null;
        if (k.GetValueKind(s.Name) != RegistryValueKind.DWord || v is not int i) throw new InvalidOperationException($"{s.Target} isn't a DWORD.");
        return i;
    }

    public void WriteDword(RegistrySetting setting, int value)
    {
        var s = Allowed(setting);
        using var root = OpenBase(s);
        using var k = root.CreateSubKey(s.Key, writable: true) ?? throw new UnauthorizedAccessException($"Can't open {s.Key}.");
        k.SetValue(s.Name, value, RegistryValueKind.DWord);
        Log($"{s.Target} set to {value}");
    }

    public void DeleteDword(RegistrySetting setting)
    {
        var s = Allowed(setting);
        using var root = OpenBase(s);
        using var k = root.OpenSubKey(s.Key, writable: true);
        k?.DeleteValue(s.Name, throwOnMissingValue: false);
        Log($"{s.Target} deleted");
    }

    /// <summary>Defender status + which code folders, package cache and build tools aren't excluded yet. Null = couldn't tell.</summary>
    private async Task<DefenderInfo?> ReadDefenderAsync(CancellationToken ct)
    {
        try
        {
            var r = await RunPowerShellAsync(DefenderProbe.Script, ct).ConfigureAwait(false);
            if (DefenderProbe.Parse(r.ExitCode == 0 ? r.Output : null) is not { } status) return null;
            if (!status.Active) return new(false, [], [], []);
            var p = ProjectLocatorPaths.Current();
            var roots = await DevProjects.FindAsync(log, ct).ConfigureAwait(false);
            var folders = ProjectLocator.CollapseSiblings(roots.Select(x => x.Path), p);
            var nuget = Path.Combine(p.UserProfile, ".nuget", "packages");
            return DefenderProbe.Plan(status, folders, Directory.Exists(nuget) ? nuget : null, DevProjects.BuildTools());
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Defender read failed: " + ex.Message); return null; }
    }

    public async Task<(bool Ok, string? Output)> RunDefenderScriptAsync(string script, CancellationToken ct)
    {
        var r = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        if (r.ExitCode != 0) Log("Defender script failed: " + r.Error);
        return (r.ExitCode == 0, r.Output);
    }

    // One cache for the whole app: several WindowsMemorySystem instances exist (memory page, benchmarks, --undo-all).
    private static StorageCleanupCache? s_cleanupCache;
    private static readonly object s_cleanupGate = new();

    public Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct)
    {
        StorageCleanupCache cache;
        lock (s_cleanupGate) cache = s_cleanupCache ??= new(async c =>
        {
            var roots = (await DevProjects.FindAsync(log, c).ConfigureAwait(false)).Select(r => r.Path).ToList();
            return await Task.Run(() => ScanStorageCleanups(ReadDevices(), Log, c, roots), c).ConfigureAwait(false);
        });
        return cache.GetAsync(refresh, ct);
    }

    private const string PersonalizeKey = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    public bool? GetTransparency()
    {
        try { return Registry.GetValue(PersonalizeKey, "EnableTransparency", null) is int v ? v != 0 : null; }
        catch (Exception ex) { Log("Transparency read failed: " + ex.Message); return null; }
    }

    /// <summary>Same value the Settings toggle writes (current user only); Explorer picks it up within a few seconds.</summary>
    public void SetTransparency(bool on) => Registry.SetValue(PersonalizeKey, "EnableTransparency", on ? 1 : 0, RegistryValueKind.DWord);

    public async Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct)
    {
        var r = await RunPowerShellAsync(MemoryProbe.EnableAutoPageFileScript, ct).ConfigureAwait(false);
        Log($"Enable automatic page file: exit={r.ExitCode} err={r.Error.Trim()}");
        return r.ExitCode == 0
            ? new(true, "Windows will manage the page file size from the next restart.")
            : new(false, "Couldn't change the page file setting (administrator rights required).");
    }

    private const string ReadPageFileScript =
        "$ErrorActionPreference='SilentlyContinue';$s=@(Get-CimInstance Win32_PageFileSetting | Select-Object Name,InitialSize,MaximumSize);" +
        "if($s.Count -gt 0){[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $s -Compress)))}";

    public async Task<string?> ReadPageFileSettingsAsync(CancellationToken ct)
    {
        var r = await RunPowerShellAsync(ReadPageFileScript, ct).ConfigureAwait(false);
        var b64 = r.Output.Trim();
        return r.ExitCode == 0 && b64.Length > 0 ? b64 : null;
    }

    public async Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct)
    {
        if (settings.Length == 0 || settings.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))) return new(false, "The saved page file settings are unreadable.");
        var script =
            "$ErrorActionPreference='Stop';" +
            $"$j=@([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{settings}')) | ConvertFrom-Json);" +
            "$c=Get-CimInstance Win32_ComputerSystem; Set-CimInstance -InputObject $c -Property @{AutomaticManagedPagefile=$false};" +
            "foreach($p in $j){ $e=Get-CimInstance Win32_PageFileSetting | Where-Object { $_.Name -eq $p.Name };" +
            " if($e){ Set-CimInstance -InputObject $e -Property @{InitialSize=[uint32]$p.InitialSize;MaximumSize=[uint32]$p.MaximumSize} }" +
            " else { New-CimInstance -ClassName Win32_PageFileSetting -Property @{Name=$p.Name;InitialSize=[uint32]$p.InitialSize;MaximumSize=[uint32]$p.MaximumSize} | Out-Null } }";
        var r = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        Log($"Restore page file: exit={r.ExitCode} err={r.Error.Trim()}");
        return r.ExitCode == 0 ? new(true, "Custom page file size restored (takes effect after a restart).") : new(false, "Couldn't restore the page file setting (administrator rights required).");
    }

    /// <summary>Runs one of this class's fixed PowerShell scripts (never user input) and returns its output.</summary>
    private async Task<(int ExitCode, string Output, string Error)> RunPowerShellAsync(string script, CancellationToken ct, TimeSpan? limit = null)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(limit ?? TimeSpan.FromSeconds(30));
            var outTask = p.StandardOutput.ReadToEndAsync(timeout.Token);
            var errTask = p.StandardError.ReadToEndAsync(timeout.Token);
            await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            return (p.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or OperationCanceledException or InvalidOperationException)
        {
            Log("PowerShell probe failed: " + ex.Message);
            return (-1, "", ex.Message);
        }
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

    public int? ReadEnabledStartupCount() => ReadStartup()?.Count(e => e.Enabled);

    private List<StartupEntry>? ReadStartup()
    {
        var list = new List<StartupEntry>();
        try
        {
            using (var run = Registry.CurrentUser.OpenSubKey(RunKey))
                if (run is not null)
                    foreach (var n in run.GetValueNames())
                        if (run.GetValue(n) is string cmd)
                            list.Add(new(n, cmd, StartupParsing.IsEnabled(GetStartupApproved(n)), StartupScope.CurrentUser));

            using (var runLm = Registry.LocalMachine.OpenSubKey(RunKey))
            using (var appLm = Registry.LocalMachine.OpenSubKey(ApprovedKey))
                if (runLm is not null)
                    foreach (var n in runLm.GetValueNames())
                        if (runLm.GetValue(n) is string cmd && !n.Equals("SecurityHealth", StringComparison.OrdinalIgnoreCase))
                            list.Add(new($"hklm:{n}", cmd, StartupParsing.IsEnabled(appLm?.GetValue(n) as byte[]), StartupScope.LocalMachine));

            using (var run32 = Registry.LocalMachine.OpenSubKey(Run32Key))
            using (var app32 = Registry.LocalMachine.OpenSubKey(Approved32Key))
                if (run32 is not null)
                    foreach (var n in run32.GetValueNames())
                        if (run32.GetValue(n) is string cmd)
                            list.Add(new($"hklm32:{n}", cmd, StartupParsing.IsEnabled(app32?.GetValue(n) as byte[]), StartupScope.LocalMachine32));

            using (var uwpRoot = Registry.CurrentUser.OpenSubKey(UwpStartupKey))
                if (uwpRoot is not null)
                    foreach (var pkg in uwpRoot.GetSubKeyNames())
                    {
                        using var pkgKey = uwpRoot.OpenSubKey(pkg);
                        if (pkgKey is null) continue;
                        foreach (var task in pkgKey.GetSubKeyNames())
                        {
                            using var taskKey = pkgKey.OpenSubKey(task);
                            if (taskKey?.GetValue("State") is int state && state is 1 or 2)
                                list.Add(new($"uwp:{pkg}\\{task}", $"{pkg}\\{task}", state == 2, StartupScope.PackagedUwp));
                        }
                    }
        }
        catch (Exception ex) { Log("Startup read failed: " + ex.Message); return null; }
        return list;
    }

    private BrowserKind? ReadDefaultBrowser()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            var progId = k?.GetValue("ProgId") as string;
            if (progId is not null)
            {
                if (progId.Contains("Chrome", StringComparison.OrdinalIgnoreCase)) return BrowserKind.Chrome;
                if (progId.Contains("MSEdge", StringComparison.OrdinalIgnoreCase)) return BrowserKind.Edge;
            }
        }
        catch (Exception ex) { Log("Default browser read failed: " + ex.Message); }
        return null;
    }

    private DeviceFacts ReadDevices()
    {
        bool? printer = null, bt = null, bio = null, pen = null, crossDevice = null, netPrinter = null, pdfPrinter = null;
        try
        {
            using var p = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Print\Printers");
            if (p is not null)
            {
                var names = p.GetSubKeyNames();
                printer = names.Any(n => !n.Contains("PDF", StringComparison.OrdinalIgnoreCase) && !n.Contains("XPS", StringComparison.OrdinalIgnoreCase)
                    && !n.Contains("OneNote", StringComparison.OrdinalIgnoreCase) && !n.Equals("Fax", StringComparison.OrdinalIgnoreCase));
                pdfPrinter = names.Any(n => n.Contains("Microsoft Print to PDF", StringComparison.OrdinalIgnoreCase) || n.Contains("XPS", StringComparison.OrdinalIgnoreCase));
                netPrinter = names.Any(n =>
                {
                    using var pk = p.OpenSubKey(n);
                    var port = pk?.GetValue("Port") as string ?? "";
                    return port.StartsWith("WSD", StringComparison.OrdinalIgnoreCase) || port.StartsWith("IP_", StringComparison.OrdinalIgnoreCase) || port.StartsWith(@"\\", StringComparison.Ordinal);
                });
            }
            using var b = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
            bt = b is not null && b.SubKeyCount > 0;
            using var f = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{53D29EF7-377C-4D14-864B-EB3A85769359}");
            bio = f is not null && f.GetSubKeyNames().Any(n => int.TryParse(n, out _));
            var dig = GetSystemMetrics(SM_DIGITIZER);
            pen = (dig & (NID_INTEGRATED_PEN | NID_EXTERNAL_PEN)) != 0;
            var cdDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "CrossDevice");
            crossDevice = Directory.Exists(cdDir) && Directory.EnumerateDirectories(cdDir).Any();
        }
        catch (Exception ex) { Log("Device probe failed: " + ex.Message); }
        return new(printer, bt, bio, pen, crossDevice, netPrinter, pdfPrinter, ReadClassicOutlook());
    }

    /// <summary>
    /// Classic Outlook (OUTLOOK.EXE) installed, from the registry only: its App Paths entry, an MSI Office Outlook InstallRoot, or a
    /// Click-to-Run product that includes Outlook (64- and 32-bit views). New Outlook (olk.exe) doesn't use the Windows Search index,
    /// so it doesn't count. Null = couldn't read (treated as "may be installed").
    /// </summary>
    private bool? ReadClassicOutlook()
    {
        try
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var appPath = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE");
                if (appPath is not null) return true;
                foreach (var ver in new[] { "16.0", "15.0", "14.0" })
                {
                    using var msi = hklm.OpenSubKey($@"SOFTWARE\Microsoft\Office\{ver}\Outlook\InstallRoot");
                    if (msi?.GetValue("Path") is string p && p.Length > 0) return true;
                }
                using var c2r = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Office\ClickToRun\Configuration");
                if (c2r is not null && ClassicOutlook.InClickToRun(c2r.GetValue("ProductReleaseIds") as string, id => c2r.GetValue(id + ".ExcludedApps") as string))
                    return true;
            }
            return false;
        }
        catch (Exception ex) { Log("Outlook probe failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// Measures every <see cref="StorageCleanupCatalog"/> category with exactly the rules and folders its cleanup uses, the review-only
    /// Grok worktree estimate (#1a, never deleted here), and %TEMP% (cleaned by the "Clean up temporary files" fix).
    /// </summary>
    public static IReadOnlyList<StorageCleanupItem> ScanStorageCleanups(DeviceFacts? devices = null, Action<string>? scanLog = null, CancellationToken ct = default,
        IReadOnlyList<string>? projectRoots = null)
    {
        var roots = StorageRoots.Current();
        var ctx = new StorageScanContext(roots, projectRoots ?? [Path.Combine(roots.UserProfile, "source", "repos")], DateTime.UtcNow, scanLog);
        var items = StorageCleanupCatalog.Scan(ctx, ct).ToList();

        // %LOCALAPPDATA%\Temp (>24h): measured only; RemediationKind.CleanTempFiles deletes it.
        var temp = Path.GetTempPath();
        if (Directory.Exists(temp))
        {
            var tempBytes = StorageCleanupEngine.Measure(StorageTarget.Contents(temp, DateTime.UtcNow.AddHours(-24)), ct).Bytes;
            if (tempBytes > 10L << 20)
                items.Add(new(StorageCleanupCatalog.TempId, "Temporary files (%TEMP% older than 24 hours)",
                    "Deletes leftover temporary installer and application files in %LOCALAPPDATA%\\Temp (the \"Clean up temporary files\" fix on the Storage checks).",
                    tempBytes, AutoCheckedByDefault: true));
        }
        return items.OrderByDescending(i => i.SizeBytes).ToList();
    }

    /// <summary>Deletes one storage cleanup category (by id only), then forgets the cached scan so the next view measures again.</summary>
    public async Task<StorageCleanResult> CleanStorageAsync(string id, CancellationToken ct)
    {
        try { return await StorageCleaner.CleanAsync(id, Log, ct).ConfigureAwait(false); }
        finally
        {
            StorageCleanupCache? cache;
            lock (s_cleanupGate) cache = s_cleanupCache;
            cache?.Invalidate();
        }
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

    private const uint SC_MANAGER_CONNECT = 0x0001, READ_CONTROL = 0x00020000, DACL_SECURITY_INFORMATION = 0x4;
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceObjectSecurity(IntPtr service, uint securityInformation, byte[]? descriptor, uint bufferSize, out uint bytesNeeded);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    /// <summary>
    /// #14: whether the service's DACL lets a signed-in, non-admin user start it (so Claude / Codex can start it again after it's set to
    /// Manual). One SCM call (QueryServiceObjectSecurity), no PowerShell. Null = couldn't read.
    /// </summary>
    private bool? ReadUsersCanStart(string serviceName)
    {
        IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
        try
        {
            scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero) return null;
            svc = OpenService(scm, serviceName, READ_CONTROL);
            if (svc == IntPtr.Zero) return null;
            QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, null, 0, out var needed);
            if (needed is 0 or > 64 * 1024) return null;
            var buf = new byte[needed];
            if (!QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, buf, needed, out _)) return null;
            var r = ServiceSecurity.UsersCanStart(buf);
            Log($"Service '{serviceName}' users can start: {r?.ToString() ?? "unknown"}");
            return r;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Log($"Service '{serviceName}' security read failed: {ex.Message}"); return null; }
        finally
        {
            if (svc != IntPtr.Zero) CloseServiceHandle(svc);
            if (scm != IntPtr.Zero) CloseServiceHandle(scm);
        }
    }

    public IReadOnlyList<string>? RunningProcessNames()
    {
        var procs = Process.GetProcesses();
        try { return procs.Select(p => { try { return p.ProcessName; } catch (InvalidOperationException) { return ""; } }).Where(n => n.Length > 0).ToList(); }
        finally { Dispose(procs); }
    }

    public async Task<ActionOutcome> RunCommandAsync(string fileName, IReadOnlyList<string> args, CancellationToken ct)
    {
        if (!MemoryCommandAllowlist.IsAllowed(fileName, args)) return new(false, "Not allowed.");
        var wsl = MemoryCommandAllowlist.IsWslShutdown(fileName, args);
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var output = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            Log($"{fileName} {string.Join(' ', args)} exit={p.ExitCode} out={output.Trim()}");
            if (wsl)
                return p.ExitCode == 0
                    ? new(true, "WSL shut down: every Linux distribution was closed. Linux starts again the next time it's used.")
                    : new(false, "WSL didn't shut down (it may not be installed or is busy).");
            return p.ExitCode == 0 ? new(true, "Build servers shut down (they start again on your next build).") : new(false, "The build servers didn't shut down.");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log($"{fileName} not found: {ex.Message}");
            return new(false, wsl ? "WSL (wsl.exe) wasn't found on this PC." : "The .NET SDK (dotnet) wasn't found on this PC.");
        }
    }

    public byte[]? GetStartupApproved(string name)
    {
        if (name.StartsWith("uwp:", StringComparison.OrdinalIgnoreCase))
        {
            using var uwp = Registry.CurrentUser.OpenSubKey(UwpStartupKey + @"\" + name[4..]);
            return uwp?.GetValue("State") is int st ? BitConverter.GetBytes(st) : null;
        }
        if (name.StartsWith("hklm32:", StringComparison.OrdinalIgnoreCase))
        {
            using var k32 = Registry.LocalMachine.OpenSubKey(Approved32Key);
            return k32?.GetValue(name[7..]) as byte[];
        }
        if (name.StartsWith("hklm:", StringComparison.OrdinalIgnoreCase))
        {
            using var klm = Registry.LocalMachine.OpenSubKey(ApprovedKey);
            return klm?.GetValue(name[5..]) as byte[];
        }
        using var k = Registry.CurrentUser.OpenSubKey(ApprovedKey);
        return k?.GetValue(name) as byte[];
    }

    public void SetStartupApproved(string name, byte[]? value)
    {
        if (name.StartsWith("uwp:", StringComparison.OrdinalIgnoreCase))
        {
            using var uwp = Registry.CurrentUser.OpenSubKey(UwpStartupKey + @"\" + name[4..], writable: true)
                ?? throw new InvalidOperationException("Not a UWP startup task");
            var state = value is null || value.Length == 0 ? 2 : (value.Length == 4 ? BitConverter.ToInt32(value, 0) : (StartupParsing.IsEnabled(value) ? 2 : 1));
            uwp.SetValue("State", state, RegistryValueKind.DWord);
            return;
        }
        if (name.StartsWith("hklm32:", StringComparison.OrdinalIgnoreCase))
        {
            var raw = name[7..];
            using var run32 = Registry.LocalMachine.OpenSubKey(Run32Key);
            if (run32?.GetValue(raw) is null) throw new InvalidOperationException("Not a 32-bit machine startup entry");
            using var k32 = Registry.LocalMachine.CreateSubKey(Approved32Key);
            if (value is null) k32.DeleteValue(raw, throwOnMissingValue: false);
            else k32.SetValue(raw, value, RegistryValueKind.Binary);
            return;
        }
        if (name.StartsWith("hklm:", StringComparison.OrdinalIgnoreCase))
        {
            var raw = name[5..];
            using var runLm = Registry.LocalMachine.OpenSubKey(RunKey);
            if (runLm?.GetValue(raw) is null) throw new InvalidOperationException("Not a machine startup entry");
            using var klm = Registry.LocalMachine.CreateSubKey(ApprovedKey);
            if (value is null) klm.DeleteValue(raw, throwOnMissingValue: false);
            else klm.SetValue(raw, value, RegistryValueKind.Binary);
            return;
        }
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

    public async Task<ActionOutcome> EndBrowserBackgroundAsync(BrowserKind kind, CancellationToken ct)
    {
        var name = BrowserPrefs.Label(kind);
        int session;
        using (var me = Process.GetCurrentProcess()) session = me.SessionId;
        var all = Process.GetProcessesByName(BrowserPrefs.ProcessName(kind));
        var procs = all.Where(p => { try { return p.SessionId == session; } catch { return false; } }).ToArray(); // never another person's session
        try
        {
            if (procs.Length == 0) return new(true, $"{name} isn't running.");
            if (procs.Any(p => { try { return !p.HasExited && p.MainWindowHandle != IntPtr.Zero; } catch { return true; } }))
                return new(false, $"{name} has a window open, so it was left running.");
            foreach (var p in procs)
                try { p.Kill(entireProcessTree: true); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { Log($"Kill {kind}/{p.Id}: {ex.Message}"); }
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline && procs.Any(p => { try { return !p.HasExited; } catch { return false; } }))
                await Task.Delay(200, ct).ConfigureAwait(false);
        }
        finally { Dispose(all); }
        var left = Process.GetProcessesByName(BrowserPrefs.ProcessName(kind));
        var n = left.Count(p => { try { return p.SessionId == session; } catch { return false; } });
        Dispose(left);
        Log($"End {kind} background processes: {n} left");
        return n == 0 ? new(true, $"Ended {name}'s background processes.") : new(false, $"Couldn't end every {name} background process.");
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
