using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.OutlookBench;

namespace OutlookBenchmark;

/// <summary>Read-only system and Outlook inventory. Nothing is changed on the PC.</summary>
internal static class Probes
{
    public static string? RunPowerShell(string script, int timeoutMs = 60_000)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEndAsync();
            p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(true); } catch { } return null; }
            return p.ExitCode == 0 ? o.Result.Trim() : null;
        }
        catch { return null; }
    }

    private const string SystemScript =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$cs=Get-CimInstance Win32_ComputerSystem; $p=@(Get-CimInstance Win32_Processor)[0]; $os=Get-CimInstance Win32_OperatingSystem;" +
        "$mem=@(Get-CimInstance Win32_PhysicalMemory); $arr=@(Get-CimInstance Win32_PhysicalMemoryArray | Where-Object { $_.Use -eq 3 });" +
        "$dn=(Get-Partition -DriveLetter $env:SystemDrive.Substring(0,1) | Get-Disk).Number; $pd=Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$dn } | Select-Object -First 1;" +
        "$vol=Get-Volume -DriveLetter $env:SystemDrive.Substring(0,1);" +
        "$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [string]$_.displayName });" +
        "$pf=(Get-CimInstance Win32_PageFileUsage | Measure-Object AllocatedBaseSize -Sum).Sum;" +
        "$net=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { if ($_.NdisPhysicalMedium -eq 9) { 'Wi-Fi' } elseif ($_.NdisPhysicalMedium -eq 14) { 'Ethernet' } else { [string]$_.MediaType } });" +
        "[pscustomobject]@{Manufacturer=[string]$cs.Manufacturer;Model=[string]$cs.Model;CpuName=[string]$p.Name;Cores=[int]$p.NumberOfCores;Threads=[int]$p.NumberOfLogicalProcessors;MaxMhz=[int]$p.MaxClockSpeed;" +
        "TotalRam=[int64]$cs.TotalPhysicalMemory;FreeRamKb=[int64]$os.FreePhysicalMemory;Modules=$mem.Count;Slots=[int](($arr | Measure-Object MemoryDevices -Sum).Sum);" +
        "RamSpeed=[int](($mem | Measure-Object ConfiguredClockSpeed -Maximum).Maximum);MaxRamKb=[int64](($arr | Measure-Object MaxCapacityEx -Sum).Sum);" +
        "DiskModel=[string]$pd.FriendlyName;DiskMedia=[string]$pd.MediaType;DiskBus=[string]$pd.BusType;DiskSize=[int64]$pd.Size;DiskFree=[int64]$vol.SizeRemaining;" +
        "Os=[string]$os.Caption;Build=[string]$os.BuildNumber;PageFileMb=[int64]$pf;Antivirus=$av;Network=($net -join ' + ')} | ConvertTo-Json -Compress";

    public static SystemProfile System(bool anonymize, bool reference)
    {
        var json = RunPowerShell(SystemScript);
        JsonElement r = default;
        var ok = false;
        try { if (json is { Length: > 0 }) { r = JsonDocument.Parse(json).RootElement; ok = true; } } catch { }
        string S(string n) => ok && r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        long L(string n) => ok && r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0;
        var av = ok && r.TryGetProperty("Antivirus", out var a) && a.ValueKind == JsonValueKind.Array ? a.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
            : ok && r.TryGetProperty("Antivirus", out var a1) && a1.ValueKind == JsonValueKind.String ? [a1.GetString()!] : new List<string>();

        double? cpu1 = null, cpuN = null, disk = null;
        if (reference)
        {
            Console.WriteLine("  Measuring processor speed…");
            cpu1 = RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner.CpuScore(1, TimeSpan.FromSeconds(3));
            cpuN = RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner.CpuScore(Environment.ProcessorCount, TimeSpan.FromSeconds(5));
            Console.WriteLine("  Measuring disk response time…");
            disk = DiskLatencyMs();
        }
        var procs = Process.GetProcesses();
        foreach (var p in procs) p.Dispose();
        var machine = anonymize ? OutlookBenchMath.Anonymize(Environment.MachineName) : Environment.MachineName;
        return new(machine, S("Manufacturer"), S("Model"), new(S("CpuName").Trim(), (int)L("Cores"), (int)L("Threads"), (int)L("MaxMhz")),
            new(L("TotalRam"), L("FreeRamKb") * 1024, (int)L("Modules"), (int)L("Slots"), L("RamSpeed") is > 0 and var sp ? (int)sp : null, L("MaxRamKb") is > 0 and var mx ? mx * 1024 : null),
            new(S("DiskModel"), S("DiskMedia"), S("DiskBus"), L("DiskSize"), L("DiskFree")),
            S("Os"), S("Build"), Math.Round(Environment.TickCount64 / 3_600_000.0, 1), L("PageFileMb") * 1048576, procs.Length,
            OnBattery(), PowerPlan(), av, S("Network") is { Length: > 0 } n ? n : null, Office365ConnectMs(), cpu1, cpuN, disk);
    }

    private static double? DiskLatencyMs()
    {
        try
        {
            var test = new RemotePCDiagnostics.Core.Stress.DiskSpeedTest(new RemotePCDiagnostics.Core.Stress.PhysicalDiskTestFileSystem(), new RemotePCDiagnostics.Core.Sensors.UnavailableSensorProvider());
            var r = test.RunAsync(new RemotePCDiagnostics.Core.Stress.DiskSpeedOptions { Duration = TimeSpan.FromSeconds(12), RequestedSizeBytes = 256L << 20, MaxRandomPhase = TimeSpan.FromSeconds(4) }).GetAwaiter().GetResult();
            return r.RandomReadIops is > 0 and var iops ? 1000.0 / iops : null;
        }
        catch { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
    private static bool? OnBattery() => GetSystemPowerStatus(out var s) ? s.ACLineStatus switch { 0 => true, 1 => false, _ => null } : null;

    private static string? PowerPlan()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "powercfg.exe"), "/getactivescheme") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
            var t = p.StandardOutput.ReadToEnd(); p.WaitForExit(5000);
            int a = t.LastIndexOf('('), b = t.LastIndexOf(')');
            return a >= 0 && b > a ? t[(a + 1)..b] : null;
        }
        catch { return null; }
    }

    /// <summary>Median TCP connect time to Microsoft 365's Outlook endpoint (what a cloud mailbox connects to at start-up).</summary>
    private static double? Office365ConnectMs()
    {
        var times = new List<double>();
        for (var i = 0; i < 3; i++)
        {
            try
            {
                using var c = new TcpClient();
                var sw = Stopwatch.StartNew();
                if (c.ConnectAsync("outlook.office365.com", 443).Wait(5000)) times.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch { }
        }
        return times.Count == 0 ? null : times.OrderBy(x => x).ElementAt(times.Count / 2);
    }

    // ---- Outlook ----
    public static string? OutlookExe() =>
        Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE", "", null) as string is { } p && File.Exists(p.Trim('"')) ? p.Trim('"') : null;

    public static string? DefaultProfile() =>
        Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook", "DefaultProfile", null) as string;

    public static OutlookProfile Outlook()
    {
        var exe = OutlookExe();
        const string c2r = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration";
        var version = Registry.GetValue(c2r, "VersionToReport", null) as string ?? (exe is null ? null : FileVersionInfo.GetVersionInfo(exe).FileVersion);
        var bitness = Registry.GetValue(c2r, "Platform", null) as string;
        var cdn = Registry.GetValue(c2r, "CDNBaseUrl", null) as string ?? "";
        var channel = cdn.Contains("492350f6-3a01-4f97-b9c0-c7c6ddf67d60") ? "Current" : cdn.Contains("55336b82-a18d-4dd6-b5f6-9e5095c314a6") ? "Monthly Enterprise"
            : cdn.Contains("7ffbc6bf-bc32-4f92-8982-f9dd17fd3114") ? "Semi-Annual Enterprise" : cdn.Contains("5440fd1f-7ecb-4221-8110-145efaa6372f") ? "Beta" : cdn.Length > 0 ? "Other" : null;
        var newDefault = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Preferences", "UseNewOutlook", null) is int u && u == 1;
        var newInstalled = Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"))
            && SafeDirs(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"), "Microsoft.OutlookForWindows_*").Any();
        var sync = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode", "SyncWindowSetting", null) is int sw ? sw : (int?)null;
        return new(exe is not null, version, bitness, channel, newDefault, newInstalled, DefaultProfile() is { Length: > 0 }, sync, MailFiles(), Addins());
    }

    private static IEnumerable<string> SafeDirs(string root, string pattern) { try { return Directory.EnumerateDirectories(root, pattern); } catch { return []; } }

    private static IReadOnlyList<MailFile> MailFiles()
    {
        var list = new List<MailFile>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        foreach (var (dir, pattern) in new[] { (Path.Combine(local, @"Microsoft\Outlook"), "*.ost"), (Path.Combine(local, @"Microsoft\Outlook"), "*.pst"), (Path.Combine(docs, "Outlook Files"), "*.pst") })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Directory.EnumerateFiles(dir, pattern))
            {
                var fi = new FileInfo(f);
                list.Add(new(Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), Math.Round(fi.Length / 1073741824.0, 2), f.StartsWith(@"\\"), fi.LastWriteTimeUtc));
            }
        }
        return list;
    }

    private static IReadOnlyList<AddinInfo> Addins()
    {
        var times = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Office\16.0\Outlook\AddInLoadTimes"))
            foreach (var n in k?.GetValueNames() ?? []) if (k!.GetValue(n) is byte[] b) times[n] = b;
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Office\16.0\Outlook\Resiliency\DisabledItems"))
            foreach (var n in k?.GetValueNames() ?? []) if (k!.GetValue(n) is byte[] b) disabled.Add(global::System.Text.Encoding.Unicode.GetString(b));

        var list = new List<AddinInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, scope, path) in new[]
        {
            (Registry.CurrentUser, "User", @"Software\Microsoft\Office\Outlook\Addins"),
            (Registry.LocalMachine, "Machine", @"Software\Microsoft\Office\Outlook\Addins"),
            (Registry.LocalMachine, "Machine (32-bit)", @"Software\WOW6432Node\Microsoft\Office\Outlook\Addins"),
            (Registry.LocalMachine, "Machine (Click-to-Run)", @"Software\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Outlook\Addins"),
        })
        {
            using var root = hive.OpenSubKey(path);
            foreach (var progId in root?.GetSubKeyNames() ?? [])
            {
                if (!seen.Add(progId)) continue;
                using var a = root!.OpenSubKey(progId);
                var name = a?.GetValue("FriendlyName") as string ?? progId;
                if (name.StartsWith('@')) name = progId; // resource reference: show the ProgID
                var raw = times.GetValueOrDefault(progId);
                list.Add(new(progId, name, scope, a?.GetValue("LoadBehavior") is int lb ? lb : null, OutlookBenchMath.ParseLoadTimes(raw), raw is null ? null : OutlookBenchMath.Hex(raw),
                    disabled.Any(d => d.Contains(progId, StringComparison.OrdinalIgnoreCase))));
            }
        }
        return list;
    }
}
