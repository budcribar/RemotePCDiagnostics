using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The Agent's run_command takes only the command lines the app sends each allowlisted tool. These list every one of them (from the
/// same constants and builders the callers use where there are some) and a few near misses that must be refused.
/// </summary>
public sealed class AdminCommandArgumentsTests
{
    private static bool Allowed(string exe, params string[] args) => AdminCommandAllowlist.TryValidateArguments(exe, args, out _);

    public static TheoryData<string, string[]> AppCommands => new()
    {
        // Windows repair and integrity scans
        { "sfc.exe", WindowsRepair.SfcArgs },
        { "sfc.exe", ["/verifyonly"] },
        { "dism.exe", WindowsRepair.DismArgs },
        { "dism.exe", WindowsRepair.AnalyzeArgs },
        { "dism.exe", WindowsRepair.CleanupArgs },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/ScanHealth"] },
        { "dism.exe", ["/English", "/Online", "/Get-CurrentEdition"] },
        { "dism.exe", ["/English", "/Get-WimInfo", @"/WimFile:D:\sources\install.wim"] },
        { "dism.exe", ["/English", "/Get-WimInfo", @"/WimFile:D:\sources\install.esd", "/Index:6"] },
        { "dism.exe", [.. WindowsRepair.DismArgs, WindowsRepair.ImageSourceArg(@"D:\sources\install.wim", 3), "/LimitAccess"] },
        { "dism.exe", [.. WindowsRepair.DismArgs, WindowsRepair.ImageSourceArg(@"\\nas\images\install.esd", 1), "/LimitAccess"] },
        // Network
        { "ipconfig.exe", ["/flushdns"] },
        { "ipconfig.exe", ["/renew"] },
        { "netsh.exe", ["wlan", "show", "interfaces"] },
        // Power and sleep
        { "powercfg.exe", ["/getactivescheme"] },
        { "powercfg.exe", ["/a"] },
        { "powercfg.exe", ["/requests"] },
        { "powercfg.exe", ["/waketimers"] },
        { "powercfg.exe", ["/lastwake"] },
        { "powercfg.exe", [.. DeviceWake.QueryArgs] },
        { "powercfg.exe", ["/setactive", RemediationService.BalancedPlanGuid] },
        { "powercfg.exe", ["/devicedisablewake", "HID Keyboard Device (001)"] },
        { "powercfg.exe", ["/deviceenablewake", "Intel(R) Wi-Fi 6 AX201 160MHz"] },
        { "powercfg.exe", ["/h", "/type", "full"] },
        { "powercfg.exe", ["/h", "/type", "reduced"] },
        // Event logs
        { "wevtutil.exe", [.. WindowsEventLog.Arguments("System", WindowsEventLog.LevelQuery(7, 1, 2), 500)] },
        { "wevtutil.exe", [.. WindowsEventLog.Arguments("Microsoft-Windows-Diagnostics-Performance/Operational", "*", 5)] },
        // Devices
        { "pnputil.exe", ["/scan-devices"] },
        { "pnputil.exe", ["/restart-device", @"USB\VID_046D&PID_C52B\5&2F1A3B4&0&2"] },
        { "pnputil.exe", ["/enable-device", @"PCI\VEN_8086&DEV_A0F0&SUBSYS_00748086&REV_20\3&11583659&0&A3"] },
        // Restarts
        { "shutdown.exe", ["/a"] },
        { "shutdown.exe", ["/r", "/t", "10", "/c", "Remote PC Diagnostics: restarting to finish undoing changes."] },
        { "shutdown.exe", ["/g", "/t", "60", "/c", "Remote PC Diagnostics: clean restart scheduled in 60 seconds. Session will automatically resume after sign-in."] },
        { "shutdown.exe", ["/g", "/t", "30", "/c", "Remote PC Diagnostics: restarting to continue the service workflow. Please save your work."] },
        { "shutdown.exe", ["/r", "/t", "60"] },
        // Support reads
        { "tpmtool.exe", ["getdeviceinformation"] },
        { "dsregcmd.exe", ["/status"] },
        { "w32tm.exe", ["/query", "/status", "/verbose"] },
    };

    [Theory]
    [MemberData(nameof(AppCommands))]
    public void Every_command_the_app_sends_is_allowed(string exe, string[] args)
    {
        Assert.True(AdminCommandAllowlist.TryResolveSystemTool(exe, out _), exe);
        Assert.True(AdminCommandAllowlist.TryValidateArguments(exe, args, out var error), error);
    }

    public static TheoryData<string, string[]> RefusedCommands => new()
    {
        // No arguments, or arguments a tool's rule doesn't know
        { "sfc.exe", [] },
        { "sfc.exe", ["/scanfile=C:\\Windows\\System32\\kernel32.dll"] },
        { "sfc.exe", ["/scannow", "/offwindir=D:\\Windows"] },
        { "dism.exe", ["/Online", "/Add-Package", "/PackagePath:C:\\x.cab"] },
        { "dism.exe", ["/Online", "/Enable-Feature", "/FeatureName:TelnetClient"] },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth", "/Source:C:\\x", "/LimitAccess"] },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth", "/Source:WIM:C:\\x.txt:1", "/LimitAccess"] },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth", "/Source:WIM:install.wim:1", "/LimitAccess"] },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth", "/Source:WIM:D:\\install.wim:x", "/LimitAccess"] },
        { "dism.exe", ["/English", "/Get-WimInfo", "/WimFile:D:\\install.wim", "/Index:0"] },
        { "dism.exe", ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth", "/Apply-Unattend:C:\\u.xml"] },
        { "ipconfig.exe", ["/all", "/flushdns"] },
        { "ipconfig.exe", ["/release"] },
        { "netsh.exe", ["advfirewall", "set", "allprofiles", "state", "off"] },
        { "netsh.exe", ["interface", "portproxy", "add", "v4tov4", "listenport=80", "connectaddress=10.0.0.1"] },
        { "netsh.exe", ["wlan", "export", "profile", "key=clear", "folder=C:\\Users\\Public"] },
        { "netsh.exe", ["add", "helper", "C:\\Users\\Public\\x.dll"] },
        { "netsh.exe", [] },
        { "powercfg.exe", ["/batteryreport", "/xml", "/output", "C:\\Windows\\System32\\x.xml"] },
        { "powercfg.exe", ["/energy", "/output", "C:\\Windows\\x.html"] },
        { "powercfg.exe", ["/import", "C:\\Users\\Public\\plan.pow"] },
        { "powercfg.exe", ["/setactive", "scheme_min"] },
        { "powercfg.exe", ["/setactive", "381b4222-f694-41f0-9685-ff5bb260df2e", "/x"] },
        { "powercfg.exe", ["/devicedisablewake", "/x"] },
        { "powercfg.exe", ["/h", "off"] },
        { "powercfg.exe", ["/setacvalueindex", "scheme_current", "sub_buttons", "lidaction", "0"] },
        { "wevtutil.exe", ["cl", "Security"] },
        { "wevtutil.exe", ["qe", "Security", "/sq:true"] },
        { "wevtutil.exe", ["qe", "C:\\Users\\Public\\x.evtx", "/lf:true"] },
        { "wevtutil.exe", ["qe", "System", "/sbm:C:\\Windows\\System32\\x.xml"] },
        { "wevtutil.exe", ["qe", "System", "/bm:C:\\Users\\Public\\b.xml"] },
        { "wevtutil.exe", ["qe", "/lf:true"] },
        { "wevtutil.exe", ["qe", "System", "/c:5", "/c:6"] },
        { "wevtutil.exe", ["qe", "System", "/f:html"] },
        { "wevtutil.exe", ["epl", "System", "C:\\x.evtx"] },
        { "wevtutil.exe", ["sl", "Security", "/e:false"] },
        { "wevtutil.exe", ["im", "C:\\Users\\Public\\manifest.man"] },
        { "pnputil.exe", ["/add-driver", "C:\\Users\\Public\\x.inf", "/install"] },
        { "pnputil.exe", ["/delete-driver", "oem1.inf", "/force"] },
        { "pnputil.exe", ["/remove-device", "USB\\VID_046D"] },
        { "pnputil.exe", ["/disable-device", "PCI\\VEN_8086"] },
        { "pnputil.exe", ["/restart-device", "/class", "Display"] },
        { "pnputil.exe", ["/enable-device", "USB\\VID_046D", "/reboot"] },
        { "pnputil.exe", ["/restart-device", "a\"b"] },
        { "shutdown.exe", [] },
        { "shutdown.exe", ["/s", "/t", "0"] },
        { "shutdown.exe", ["/a", "/m", "\\\\server"] },
        { "shutdown.exe", ["/r", "/m", "\\\\server", "/t", "0"] },
        { "shutdown.exe", ["/r", "/f"] },
        { "shutdown.exe", ["/r", "/t", "315360000"] },
        { "shutdown.exe", ["/r", "/t"] },
        { "shutdown.exe", ["/r", "/t", "10", "/t", "20"] },
        { "shutdown.exe", ["/r", "/o"] },
        { "shutdown.exe", ["/r", "/c", "line\nbreak"] },
        { "tpmtool.exe", ["clear"] },
        { "tpmtool.exe", ["gatherlogs", "C:\\Windows\\System32"] },
        { "dsregcmd.exe", ["/leave"] },
        { "dsregcmd.exe", ["/debug"] },
        { "w32tm.exe", ["/config", "/manualpeerlist:evil.example", "/update"] },
        { "w32tm.exe", ["/resync"] },
        { "w32tm.exe", ["/register"] },
        // A tool that isn't on the allowlist has no rule either
        { "defrag.exe", ["C:", "/L"] },
        { "reg.exe", ["query", "HKLM"] },
    };

    [Theory]
    [MemberData(nameof(RefusedCommands))]
    public void Commands_the_app_never_sends_are_refused(string exe, string[] args)
    {
        Assert.False(AdminCommandAllowlist.TryValidateArguments(exe, args, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Defrag_is_no_longer_on_the_allowlist()
    {
        // Volumes are optimized through the Agent's own OptimizeVolume script, never defrag.exe from the app.
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("defrag.exe", out _));
    }

    [Fact]
    public void Options_match_without_regard_to_case()
    {
        Assert.True(Allowed("SFC.EXE", "/SCANNOW"));
        Assert.True(Allowed(@"C:\Windows\System32\ipconfig.exe", "/FlushDNS"));
        Assert.True(Allowed("powercfg.exe", "/SetActive", "381B4222-F694-41F0-9685-FF5BB260DF2E"));
    }

    [Fact]
    public void Battery_report_runs_without_the_Agent()
    {
        var args = StandbyDrain.Args(Path.Combine(Path.GetTempPath(), "rpcd-battery-test.xml"));
        Assert.True(AdminCommandAllowlist.RunsWithoutAdmin(DeviceWake.PowerCfg, args));
        Assert.False(AdminCommandAllowlist.TryValidateArguments(DeviceWake.PowerCfg, args, out _));
        Assert.False(AdminCommandAllowlist.RunsWithoutAdmin(DeviceWake.PowerCfg, ["/requests"]));
        Assert.False(AdminCommandAllowlist.RunsWithoutAdmin(WindowsEventLog.Wevtutil, ["/batteryreport"]));
    }

    [Fact]
    public async Task Runner_runs_the_battery_report_itself_and_sends_other_admin_tools_to_the_Agent()
    {
        var launcher = new ScriptedLauncher((_, _) => new ProcessResult(0, "local", ""));
        var bridge = new RecordingBridge();
        var runner = new SystemCommandRunner(launcher, elevatedBridge: bridge, isProcessElevated: () => false);

        var report = await runner.RunAsync(DeviceWake.PowerCfg, StandbyDrain.Args(@"C:\Temp\r.xml"), CancellationToken.None);
        var requests = await runner.RunAsync(DeviceWake.PowerCfg, ["/requests"], CancellationToken.None);

        Assert.Equal("local", report!.StdOut);
        Assert.Equal("agent", requests!.StdOut);
        var sent = Assert.Single(bridge.Calls);
        Assert.Equal(["/requests"], sent);
    }

    private sealed class RecordingBridge : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public List<IReadOnlyList<string>> Calls { get; } = [];

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null)
        {
            Calls.Add(arguments.ToArray());
            return Task.FromResult<ProcessResult?>(new ProcessResult(0, "agent", ""));
        }

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }
}
