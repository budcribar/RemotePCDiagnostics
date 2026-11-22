using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

// The four checks that moved from osquery (and one PowerShell script) to WMI and the registry, replayed from recorded PCs: each matches its
// approved snapshot, shows what the old path showed on the same PC at the same moment, and survives damaged answers. A recording made before
// the recorder knew a check skips that check's tests.

/// <summary>Hardware inventory (the Osquery check).</summary>
public sealed class HardwareInventoryReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiHardwareInventorySource.ComputerSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(HardwareInventory.SystemSql);

    internal static AreaReport Report(DiagnosticResult r) => HardwareInventoryReport.Build((HardwareInventory)r.Payload!, r.Status, r.Message);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI hardware answers.");
        var result = await pc.Inventory().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Osquery", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery hardware answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = WithoutGains(Report(await pc.Inventory().RefreshAsync(null, ct)));
        var old = WithoutGains(Report(await new ReplayedPc(rec).InventoryOld().RefreshAsync(null, ct)));
        var diffs = ReportDiff.Between(old, now, Live);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    /// <summary>
    /// What WMI shows that osquery doesn't, left out of both before comparing: the motherboard (osquery's board fields are empty on Windows),
    /// the memory type (osquery says Unknown), the graphics adapter's name (osquery shows the chip, "AMD Radeon Graphics Processor (0x164C)";
    /// WMI the name Device Manager shows, "AMD Radeon(TM) Graphics"), and a connected adapter's link speed (osquery reports 0).
    /// </summary>
    private static AreaReport WithoutGains(AreaReport r) => r with
    {
        Cards = r.Cards.Select(c => c.Id switch
        {
            "system" => c with { Rows = c.Rows.Where(x => x.Values[0] != "Motherboard").ToList() },
            "memory" => c with { Rows = c.Rows.Select(x => Blank(x, 3)).ToList() },
            "gpu" => c with { Headline = "", Rows = c.Rows.Select(x => Blank(x, 0)).ToList() },
            "network" => c with { Rows = c.Rows.Select(x => Blank(x, 4)).ToList() },
            _ => c,
        }).ToList(),
    };

    private static AreaRow Blank(AreaRow row, int column) =>
        row with { Values = row.Values.Select((v, i) => i == column ? "" : v).ToList() };

    /// <summary>The processor's load and current clock change from moment to moment; the two paths read them seconds apart.</summary>
    private static bool Live(AreaCard card, AreaRow row) =>
        row.Values.Count > 0 && (row.Values[0].Contains("load", StringComparison.OrdinalIgnoreCase) || row.Values[0].Contains("current", StringComparison.OrdinalIgnoreCase));

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI hardware answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => DamagedRuns.CommonProblems(Report(r)), maxRows: 3,
            ("WMI", pc => pc.Inventory()), ("osquery", pc => pc.InventoryOld()));
    }
}

/// <summary>Services.</summary>
public sealed class ServicesReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiServiceSource.Sql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryServiceSource.Sql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI services answer.");
        var result = await pc.Services().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Services", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery services answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.Services().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).ServicesOld().RefreshAsync(null, ct)).Payload!;
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI services answer.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.Services()), ("osquery", pc => pc.ServicesOld()));
    }
}

/// <summary>Device Manager and drivers.</summary>
public sealed class DeviceDriversReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiDeviceDriverSource.DriversSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryDeviceDriverSource.DriversSql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI driver answers.");
        var result = await pc.DeviceDrivers().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "DeviceDrivers", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery driver answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.DeviceDrivers().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).DeviceDriversOld().RefreshAsync(null, ct)).Payload!;
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI driver answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.DeviceDrivers()), ("PowerShell + osquery", pc => pc.DeviceDriversOld()));
    }
}

/// <summary>Programs and updates.</summary>
public sealed class ProgramsReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiProgramsSource.OsSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryProgramsSource.ProgramsSql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI programs answers.");
        var result = await pc.Programs().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Programs", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc) && pc.Has(c => c.Kind == RecordedCall.PackagesKind),
            "This recording doesn't hold the WMI, Store-app and osquery programs answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.Programs().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).ProgramsOld().RefreshAsync(null, ct)).Payload!;

        // osquery also lists every Store package, frameworks and parts of Windows included; the new path lists only the apps among them
        // (PackageList.Apps). A program only osquery lists must be one of those packages.
        var packages = await new ReplayedPc(rec).Packages.ReadPackagesAsync(ct);
        var notApps = (packages.Rows ?? []).Where(p => !PackageList.IsApp(p)).Select(p => p.Str(PackageList.DisplayName)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var diffs = ReportDiff.Between(WithoutGains(old, notApps), WithoutGains(now, notApps));
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    /// <summary>
    /// Leaves out what only one path has on purpose: Windows' display version ("26H2"; osquery's os_version has none), and the Store packages
    /// that aren't apps (osquery lists them; see above). The programs headline counts them, so it isn't compared.
    /// </summary>
    private static AreaReport WithoutGains(AreaReport r, IReadOnlySet<string> notApps) => r with
    {
        Cards = r.Cards.Select(c => c.Id switch
        {
            "windows" => c with { Meta = "", Rows = c.Rows.Where(x => x.Values[0] != "Version").ToList() },
            "programs" => c with { Headline = "", Meta = "", Rows = c.Rows.Where(x => !notApps.Contains(x.Values[0])).ToList() },
            _ => c,
        }).ToList(),
    };

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI programs answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI + registry", pc => pc.Programs()), ("osquery", pc => pc.ProgramsOld()));
    }
}

/// <summary>
/// Known failures made from each recorded PC (as BatteryPower's are made from the sample): one edit to the real answers, one right verdict.
/// They run on every recording that holds the check's WMI answers.
/// </summary>
public sealed class InventoryKnownFailureTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static async Task<AreaReport> RunAsync(MachineRecording rec, Func<ReplayedPc, IDiagnosticModule> check)
    {
        var r = await check(new ReplayedPc(rec)).RefreshAsync(null, TestContext.Current.CancellationToken);
        return r.Payload as AreaReport ?? HardwareInventoryReplayTests.Report(r);
    }

    private static MachineRecording Load(string name, string query)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasWmi(query), "This recording doesn't hold this check's WMI answers.");
        return rec;
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task A_stopped_automatic_service_is_listed(string name)
    {
        var rec = Load(name, WmiServiceSource.Sql).SetRows("Name", "Dhcp", "State", "Stopped").SetRows("Name", "Dhcp", "StartMode", "Auto");
        var stopped = (await RunAsync(rec, pc => pc.Services())).Cards.Single(c => c.Id == "stopped");
        Assert.Equal(AreaLevel.Warning, stopped.Level);
        Assert.Contains(stopped.Rows, r => r.Key == "Dhcp");
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task A_device_with_a_Device_Manager_error_is_a_warning_with_a_restart(string name)
    {
        var rec = Load(name, WmiDeviceDriverSource.ProblemDevicesSql).AddWmiRow("Win32_PnPEntity", new Dictionary<string, object?>
        {
            ["Name"] = "Test USB Camera", ["PNPClass"] = "Camera", ["DeviceID"] = @"USB\VID_0000&PID_0000\1", ["ConfigManagerErrorCode"] = 28, ["Status"] = "Error",
        });
        var problems = (await RunAsync(rec, pc => pc.DeviceDrivers())).Cards.Single(c => c.Id == "problems");
        Assert.Equal(AreaLevel.Warning, problems.Level);
        var row = Assert.Single(problems.Rows, r => r.Values[0] == "Test USB Camera");
        Assert.Contains(row.Actions!, a => a.Kind == RemediationKind.RestartDevice);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task No_update_in_90_days_is_a_warning_with_Windows_Update(string name)
    {
        var rec = Load(name, WmiProgramsSource.UpdatesSql);
        var old = DateOnly.FromDateTime(rec.CapturedAt.DateTime).AddDays(-90).ToString("M/d/yyyy", System.Globalization.CultureInfo.InvariantCulture);
        rec = rec.SetWmi("Win32_QuickFixEngineering", "InstalledOn", old);
        var updates = (await RunAsync(rec, pc => pc.Programs())).Cards.Single(c => c.Id == "updates");
        Assert.Equal(AreaLevel.Warning, updates.Level);
        Assert.Equal("Last update 3 months ago", updates.Headline);
        Assert.Contains(updates.Actions!, a => a.Kind == RemediationKind.CheckAndInstallWindowsUpdates);
    }

    /// <summary>An installed app made old (for troubleshooting replays): the old version is what the report shows.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task An_outdated_app_shows_its_old_version(string name)
    {
        var rec = Load(name, WmiProgramsSource.OsSql);
        var app = rec.Calls.Where(c => c.Kind == RecordedCall.RegistryKind).SelectMany(c => c.Rows ?? [])
            .Select(r => r.TryGetValue("DisplayName", out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null)
            .FirstOrDefault(n => n is { Length: > 0 });
        Assert.SkipWhen(app is null, "This recording lists no programs.");
        rec = rec.SetRows("DisplayName", app!, "DisplayVersion", "1.0.0.1");
        var programs = (await RunAsync(rec, pc => pc.Programs())).Cards.Single(c => c.Id == "programs");
        Assert.Contains(programs.Rows, r => r.Values[0] == app && r.Values[1] == "1.0.0.1");
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task A_memory_read_that_fails_still_shows_the_installed_total(string name)
    {
        var rec = Load(name, WmiHardwareInventorySource.MemorySql).FailWmi("Win32_PhysicalMemory", "Access denied");
        var r = await new ReplayedPc(rec).Inventory().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        var memory = HardwareInventoryReplayTests.Report(r).Cards.Single(c => c.Id == "memory");
        Assert.EndsWith("GB", memory.Headline);
    }
}

/// <summary>Drivers made old or unsigned (for troubleshooting replays), on every recording with WMI driver answers.</summary>
public sealed class DriverKnownFailureTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static (MachineRecording Rec, string Device) LoadWithDevice(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasWmi(WmiDeviceDriverSource.DriversSql), "This recording doesn't hold the WMI driver answers.");
        var device = rec.Calls.Where(c => c.Query == WmiDeviceDriverSource.DriversSql).SelectMany(c => c.Rows ?? [])
            .Select(r => r.TryGetValue("DeviceName", out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString()!.Trim() : "")
            .First(n => n.Length > 0);
        return (rec, device);
    }

    private static async Task<AreaCard> DriversAsync(MachineRecording rec) =>
        ((AreaReport)(await new ReplayedPc(rec).DeviceDrivers().RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!)
        .Cards.Single(c => c.Id == "drivers");

    /// <summary>The report lists the old version and date; nothing flags a driver for its age (there is no rule for that yet).</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task An_outdated_driver_shows_its_old_version_and_date(string name)
    {
        var (rec, device) = LoadWithDevice(name);
        rec = rec.SetRows("DeviceName", device, "DriverVersion", "1.0.0.1").SetRows("DeviceName", device, "DriverDate", "20150101000000.000000-000");
        var drivers = await DriversAsync(rec);
        Assert.Contains(drivers.Rows, r => r.Values[0] == device && r.Values[3] == "1.0.0.1" && r.Values[4] == "1 Jan 2015");
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task An_unsigned_driver_is_a_warning(string name)
    {
        var (rec, device) = LoadWithDevice(name);
        var drivers = await DriversAsync(rec.SetRows("DeviceName", device, "IsSigned", false));
        Assert.Equal(AreaLevel.Warning, drivers.Level);
        Assert.Contains(drivers.Rows, r => r.Values[0] == device && r.Level == AreaLevel.Warning);
    }
}
