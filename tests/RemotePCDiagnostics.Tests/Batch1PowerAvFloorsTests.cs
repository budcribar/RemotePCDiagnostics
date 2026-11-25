using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public sealed class Batch1PowerAvFloorsTests
{
    private sealed class FakeBatteryPowerSource(
        Queue<IReadOnlyList<BatteryStatus>?> batteries,
        Queue<ProcessorPerformanceSample?> perfSamples,
        string? plan = "Balanced",
        PowerPolicySnapshot? policy = null) : IBatteryPowerSource
    {
        public int BatteryReads { get; private set; }
        public int PerfReads { get; private set; }

        public Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct)
        {
            BatteryReads++;
            return Task.FromResult(batteries.Count > 1 ? batteries.Dequeue() : batteries.Peek());
        }

        public Task<string?> ReadActivePlanAsync(CancellationToken ct) => Task.FromResult(plan);

        public Task<ProcessorPerformanceSample?> ReadProcessorPerformanceAsync(CancellationToken ct)
        {
            PerfReads++;
            return Task.FromResult(perfSamples.Count > 1 ? perfSamples.Dequeue() : perfSamples.Peek());
        }

        public Task<PowerPolicySnapshot?> ReadPowerPolicyAsync(CancellationToken ct) => Task.FromResult(policy);
    }

    private sealed class FakeAntivirusSource(AntivirusInventoryResult result) : IAntivirusProductSource
    {
        public Task<AntivirusInventoryResult> ReadAsync(CancellationToken ct = default) => Task.FromResult(result);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> handler) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
            Task.FromResult(handler(wmiNamespace, wql));
    }

    private sealed class FakeRegistry : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(WmiQueryResult.Failed(read.Location, read.Describe(), "not set"));
    }

    private sealed class FakeProbes(
        BenchmarkConditions conditions,
        Queue<PerformanceLimitSample?>? perfLimits = null) : IBenchmarkProbes
    {
        public int PerfLimitReads { get; private set; }
        public BenchmarkConditions ReadConditions() => conditions;
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<IdleSample?>(null);
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);

        public Task<PerformanceLimitSample?> ReadPerformanceLimitAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            PerfLimitReads++;
            if (perfLimits is null || perfLimits.Count == 0)
                return Task.FromResult<PerformanceLimitSample?>(null);
            return Task.FromResult(perfLimits.Count > 1 ? perfLimits.Dequeue() : perfLimits.Peek());
        }
    }

    // ---- 1a: Battery & Power ----

    [Fact]
    public async Task BatteryPower_HealthyAc_FastPathSkipsConfirmationDelay()
    {
        var healthy = new BatteryStatus("BAT1", "Lenovo", "LiP", "AC Power", 80, 50000, 46000, 120,
            PowerOnline: true, IsCharging: false, IsDischarging: false, DischargeRateMw: null, ChargeRateMw: null);
        var src = new FakeBatteryPowerSource(
            new Queue<IReadOnlyList<BatteryStatus>?>([[healthy]]),
            new Queue<ProcessorPerformanceSample?>([new ProcessorPerformanceSample(100, 100)]),
            policy: new PowerPolicySnapshot("Balanced", 100));

        var delays = 0;
        var mod = new BatteryPowerModule(src, delay: (_, _) => { delays++; return Task.CompletedTask; });
        var res = await mod.RefreshAsync(null, TestContext.Current.CancellationToken);

        Assert.Equal(0, delays);
        Assert.Equal(1, src.BatteryReads);
        Assert.Equal(1, src.PerfReads);
        Assert.Equal(DiagnosticStatus.Ok, res.Status);
    }

    [Fact]
    public async Task BatteryPower_DischargingOnAc_ConfirmedInTwoSamples_Warns()
    {
        var draining = new BatteryStatus("BAT1", "Dell", "LiP", "AC Power", 65, 60000, 55000, 80,
            PowerOnline: true, IsCharging: false, IsDischarging: true, DischargeRateMw: 14500);
        var src = new FakeBatteryPowerSource(
            new Queue<IReadOnlyList<BatteryStatus>?>([[draining], [draining]]),
            new Queue<ProcessorPerformanceSample?>([new ProcessorPerformanceSample(100, 100)]));

        var delays = 0;
        var mod = new BatteryPowerModule(src, delay: (d, _) => { Assert.Equal(BatteryPowerModule.ConfirmationDelay, d); delays++; return Task.CompletedTask; });
        var res = await mod.RefreshAsync(null, TestContext.Current.CancellationToken);
        var report = (AreaReport)res.Payload!;

        Assert.Equal(1, delays);
        Assert.Equal(2, src.BatteryReads);
        Assert.Equal(DiagnosticStatus.Warning, res.Status);
        var batCard = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(AreaLevel.Warning, batCard.Level);
        Assert.Contains("discharging", batCard.Headline, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BatteryPower_TransientSingleSampleDischarge_NotFlagged()
    {
        var draining = new BatteryStatus("BAT1", "Dell", "LiP", "AC Power", 65, 60000, 55000, 80,
            PowerOnline: true, IsCharging: false, IsDischarging: true, DischargeRateMw: 8000);
        var settled = draining with { IsDischarging = false, DischargeRateMw = null };
        var src = new FakeBatteryPowerSource(
            new Queue<IReadOnlyList<BatteryStatus>?>([[draining], [settled]]),
            new Queue<ProcessorPerformanceSample?>([new ProcessorPerformanceSample(100, 100)]));

        var delays = 0;
        var mod = new BatteryPowerModule(src, delay: (_, _) => { delays++; return Task.CompletedTask; });
        var res = await mod.RefreshAsync(null, TestContext.Current.CancellationToken);

        Assert.Equal(1, delays);
        Assert.Equal(DiagnosticStatus.Ok, res.Status);
    }

    [Fact]
    public async Task BatteryPower_HeldBackOnAc_ConfirmedBelow90_Warns_AndZeroIgnored()
    {
        var acBat = new BatteryStatus("BAT1", "HP", "LiP", "AC Power", 100, 50000, 48000, 40, PowerOnline: true, IsDischarging: false);
        var srcWarn = new FakeBatteryPowerSource(
            new Queue<IReadOnlyList<BatteryStatus>?>([[acBat]]),
            new Queue<ProcessorPerformanceSample?>([new ProcessorPerformanceSample(45, 50), new ProcessorPerformanceSample(48, 52)]));
        var delays = 0;
        var resWarn = await new BatteryPowerModule(srcWarn, delay: (_, _) => { delays++; return Task.CompletedTask; })
            .RefreshAsync(null, TestContext.Current.CancellationToken);
        var planCard = ((AreaReport)resWarn.Payload!).Cards.Single(c => c.Id == "plan");
        Assert.Equal(1, delays);
        Assert.Equal(AreaLevel.Warning, planCard.Level);
        Assert.Contains(planCard.Rows, r => r.Values[1].Contains("held back while plugged in", StringComparison.OrdinalIgnoreCase));

        // Zero or failed perf counter must be treated as unknown (omitted, never Warning, no delay).
        var srcZero = new FakeBatteryPowerSource(
            new Queue<IReadOnlyList<BatteryStatus>?>([[acBat]]),
            new Queue<ProcessorPerformanceSample?>([null]));
        var zeroDelays = 0;
        var resZero = await new BatteryPowerModule(srcZero, delay: (_, _) => { zeroDelays++; return Task.CompletedTask; })
            .RefreshAsync(null, TestContext.Current.CancellationToken);
        var zeroPlan = ((AreaReport)resZero.Payload!).Cards.Single(c => c.Id == "plan");
        Assert.Equal(0, zeroDelays);
        Assert.Equal(AreaLevel.Ok, zeroPlan.Level);
        Assert.DoesNotContain(zeroPlan.Rows, r => r.Values[0].Contains("performance limit", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(100, AreaLevel.Ok, false)]
    [InlineData(99, AreaLevel.Warning, true)]
    [InlineData(50, AreaLevel.Warning, true)]
    [InlineData(null, AreaLevel.Ok, false)]
    public void BatteryPower_ConfiguredAcMaxProcessorState_WordingAndLevel(int? acCap, AreaLevel expectedLevel, bool expectWarningNote)
    {
        var policy = new PowerPolicySnapshot("Best performance", acCap);
        var report = BatteryPowerModule.Build([], "Balanced", policy: policy);
        var planCard = report.Cards.Single(c => c.Id == "plan");
        Assert.Equal(expectedLevel, planCard.Level);
        Assert.Contains(planCard.Rows, r => r.Values[0] == "Power mode" && r.Values[1] == "Best performance");
        if (acCap is null)
            Assert.DoesNotContain(planCard.Rows, r => r.Values[0].Contains("Configured maximum processor state"));
        else
            Assert.Contains(planCard.Rows, r => r.Values[0].Contains("Configured maximum processor state"));

        if (expectWarningNote)
        {
            Assert.Contains($"Configured maximum processor state on AC is {acCap}%", planCard.Note ?? "");
            Assert.DoesNotContain("Turbo Boost is off", planCard.Note ?? "", StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- 1b: Security Essentials / Antivirus ----

    [Fact]
    public void Antivirus_ConfirmedStates_SeparatedFromMachineVerdict()
    {
        // Active third-party + stale expired registration -> machine is still OK, stale product listed in rows.
        var activePlusStale = new SecurityFacts(true, "UEFI", "Professional", 1, new(true, "2.0", true, "AMD", "Possible"))
        {
            DefenderMode = "Passive mode",
            Antivirus = ["Bitdefender Antivirus", "Old McAfee"],
            AntivirusProducts =
            [
                new("Bitdefender Antivirus", AntivirusProductState.On, AntivirusSignatureStatus.UpToDate),
                new("Old McAfee", AntivirusProductState.Expired, AntivirusSignatureStatus.OutOfDate),
            ],
            AntivirusInventoryStatus = AntivirusInventoryStatus.Ok,
        };
        var card1 = SecurityEssentialsModule.Build(activePlusStale).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Ok, card1.Level);
        Assert.Equal("Protected by Bitdefender Antivirus", card1.Headline);
        Assert.Contains(card1.Rows, r => r.Values[0].Contains("Old McAfee") && r.Values[1].Contains("Expired"));

        // Expired third-party alone -> Error (no longer false OK!).
        var expiredOnly = activePlusStale with
        {
            Antivirus = ["Norton"],
            AntivirusProducts = [new("Norton", AntivirusProductState.Expired, AntivirusSignatureStatus.OutOfDate)],
        };
        var card2 = SecurityEssentialsModule.Build(expiredOnly).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Error, card2.Level);
        Assert.Contains("expired", card2.Headline, StringComparison.OrdinalIgnoreCase);

        // Snoozed third-party alone -> Warning.
        var snoozed = activePlusStale with
        {
            Antivirus = ["Avast"],
            AntivirusProducts = [new("Avast", AntivirusProductState.Snoozed, AntivirusSignatureStatus.UpToDate)],
        };
        var card3 = SecurityEssentialsModule.Build(snoozed).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Warning, card3.Level);

        // Unconfirmed WMI-only registration -> Neutral (never OK!).
        var unconfirmed = activePlusStale with
        {
            Antivirus = ["MysteryAV"],
            AntivirusProducts = [new("MysteryAV", AntivirusProductState.Unknown, AntivirusSignatureStatus.Unknown, "wmi")],
            AntivirusInventoryStatus = AntivirusInventoryStatus.Unavailable,
        };
        var card4 = SecurityEssentialsModule.Build(unconfirmed).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Neutral, card4.Level);
        Assert.Contains("could not be confirmed", card4.Headline, StringComparison.OrdinalIgnoreCase);

        // Two active AVs (Defender Normal + 3rd party On) -> Warning.
        var twoActive = activePlusStale with
        {
            DefenderMode = "Normal",
            RealTimeProtection = true,
            AntivirusProducts = [new("Bitdefender Antivirus", AntivirusProductState.On, AntivirusSignatureStatus.UpToDate)],
        };
        var card5 = SecurityEssentialsModule.Build(twoActive).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Warning, card5.Level);
        Assert.Contains("fighting", card5.Headline, StringComparison.OrdinalIgnoreCase);

        // Empty confirmed COM enumeration with no Defender -> Error (distinct from unavailable!).
        var emptyConfirmed = new SecurityFacts(true, "UEFI", "Professional", 1, null)
        {
            DefenderMode = null,
            AntivirusProducts = [],
            AntivirusInventoryStatus = AntivirusInventoryStatus.Ok,
        };
        var card6 = SecurityEssentialsModule.Build(emptyConfirmed).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Error, card6.Level);
        Assert.Equal("No active antivirus", card6.Headline);

        // Both COM and WMI unavailable -> Neutral.
        var bothUnavailable = emptyConfirmed with { AntivirusInventoryStatus = AntivirusInventoryStatus.Unavailable };
        var card7 = SecurityEssentialsModule.Build(bothUnavailable).Cards.Single(c => c.Id == "antivirus");
        Assert.Equal(AreaLevel.Neutral, card7.Level);
        Assert.Equal("Antivirus not reported", card7.Headline);
    }

    [Fact]
    public async Task WmiSecurityEssentialsSource_PartialAndUnavailableComFallback_AndReplayRoundTrip()
    {
        var wmiRows = new List<WmiRow>
        {
            new(new Dictionary<string, JsonElement> { ["displayName"] = JsonSerializer.SerializeToElement("WmiOnlyAV") }),
        };
        var wmi = new FakeWmi((ns, sql) =>
            sql == WmiSecurityEssentialsSource.AntivirusSql
                ? new WmiQueryResult(ns, sql, wmiRows)
                : WmiQueryResult.Failed(ns, sql, "not needed"));

        var partial = new AntivirusInventoryResult(AntivirusInventoryStatus.Incomplete,
            [new("ComConfirmedAV", AntivirusProductState.On, AntivirusSignatureStatus.UpToDate)]);
        var src = new WmiSecurityEssentialsSource(wmi, new FakeRegistry(), new SystemCommandRunner(), new FakeAntivirusSource(partial));
        var facts = await src.ReadAsync(null, TestContext.Current.CancellationToken);

        Assert.NotNull(facts);
        Assert.Equal(AntivirusInventoryStatus.Incomplete, facts!.AntivirusInventoryStatus);
        Assert.Contains(facts.AntivirusProducts, p => p.Name == "ComConfirmedAV" && p.State == AntivirusProductState.On);
        Assert.Contains(facts.AntivirusProducts, p => p.Name == "WmiOnlyAV" && p.State == AntivirusProductState.Unknown);

        // Replay round-trip for RecordedCall.AntivirusKind
        var recorded = RecordedCall.FromAntivirus(partial);
        var replay = new RecordingReplay([recorded]);
        var replayed = await replay.AntivirusProducts.ReadAsync(TestContext.Current.CancellationToken);
        Assert.Equal(AntivirusInventoryStatus.Incomplete, replayed.Status);
        Assert.Single(replayed.Products);
        Assert.Equal("ComConfirmedAV", replayed.Products[0].Name);
        Assert.Equal(AntivirusProductState.On, replayed.Products[0].State);
    }

    // ---- 1c: Hardware Floors ----

    [Fact]
    public void DriveHealth_BootVolumeOnHdd_Warns_SecondaryHddDoesNot()
    {
        var hddBoot = new DriveHealth("ST1000", "S1", "HDD", "SATA", "Healthy", "OK", 1_000_000_000_000, 35, null, 0, 0, 1000, Letters: "C");
        var report1 = DriveHealthModule.Build([hddBoot], systemDriveLetter: 'C');
        Assert.Equal(DiagnosticStatus.Warning, report1.Status);
        Assert.Contains(DriveHealthModule.HddBootWarning, report1.Cards.Single(c => c.Id == "drive0").Note ?? "");

        var unspecSpindle = new DriveHealth("OldDisk", "S2", "Unspecified", "SATA", "Healthy", "OK", 500_000_000_000, 35, null, 0, 0, 1000, Letters: "C", SpindleSpeedRpm: 7200);
        var report2 = DriveHealthModule.Build([unspecSpindle], systemDriveLetter: 'C');
        Assert.Equal(DiagnosticStatus.Warning, report2.Status);

        var ssdBoot = new DriveHealth("NVMe0", "S3", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 38, 5, 0, 0, 500, Letters: "C");
        var secondaryHdd = hddBoot with { Letters = "D" };
        var report3 = DriveHealthModule.Build([ssdBoot, secondaryHdd], systemDriveLetter: 'C');
        Assert.Equal(DiagnosticStatus.Ok, report3.Status);
    }

    [Fact]
    public void HardwareInventory_RamFloor_And_UpgradeableSlotNote_ExcludesLpddr()
    {
        static HardwareInventory InvWith(params MemoryDevice[] dimms) =>
            new(
                new InventorySection<SystemInfo>(HardwareInventory.SystemSql, [], null),
                new InventorySection<CpuInfo>(HardwareInventory.CpuSql, [], null),
                new InventorySection<MemoryDevice>(HardwareInventory.MemorySql, dimms, null),
                new InventorySection<DiskInfo>(HardwareInventory.DiskSql, [], null));

        // 4 GB -> Warning
        var lowRam = HardwareInventoryReport.Build(InvWith(
            new("DIMM0", "BANK0", "SODIMM", "DDR4", 4096, 3200, 3200, "Crucial", "P1", "S1"),
            new("DIMM1", "BANK1", "", "", null, null, null, "", "", "")), DiagnosticStatus.Ok, null);
        var lowCard = lowRam.Cards.Single(c => c.Id == "memory");
        Assert.Equal(AreaLevel.Warning, lowCard.Level);
        Assert.Contains("dual-channel", lowCard.Note ?? "", StringComparison.OrdinalIgnoreCase);

        // 8 GB -> Ok + minimum info note
        var eightGb = HardwareInventoryReport.Build(InvWith(
            new("DIMM0", "BANK0", "SODIMM", "DDR4", 4096, 3200, 3200, "Crucial", "P1", "S1"),
            new("DIMM1", "BANK1", "SODIMM", "DDR4", 4096, 3200, 3200, "Crucial", "P1", "S2")), DiagnosticStatus.Ok, null);
        var eightCard = eightGb.Cards.Single(c => c.Id == "memory");
        Assert.Equal(AreaLevel.Ok, eightCard.Level);
        Assert.Contains("8 GB is the practical minimum", eightCard.Note ?? "");
        Assert.DoesNotContain("dual-channel", eightCard.Note ?? "");

        // 1 of 2 LPDDR5 -> no dual-channel upgrade note
        var lpddr = HardwareInventoryReport.Build(InvWith(
            new("Row0", "BANK0", "SODIMM", "LPDDR5", 16384, 6400, 6400, "Samsung", "P2", "S3"),
            new("Row1", "BANK1", "", "", null, null, null, "", "", "")), DiagnosticStatus.Ok, null);
        Assert.Null(lpddr.Cards.Single(c => c.Id == "memory").Note);
    }

    // ---- 1d: Benchmark Conditions & CPU-Test Sampler ----

    [Fact]
    public async Task BenchmarkRunner_SamplesLowestPerfLimitDuringCpuTests_AndHandlesTiedPowerSources()
    {
        var startCond = new BenchmarkConditions(false, 52, "Balanced", "Best performance", AcMaxProcessorStatePercent: 99, DischargingOnAc: true);

        // Tied minima (45% on AC and 45% on battery) -> power source becomes "unknown".
        var tiedProbes = new FakeProbes(startCond, new Queue<PerformanceLimitSample?>([
            new(0, "ac"), // invalid 0 ignored
            new(70, "ac"),
            new(45, "ac"),
            new(45, "battery"),
        ]));
        var runner = new BenchmarkRunner(tiedProbes, delay: (_, _) => Task.CompletedTask);
        var settings = new BenchmarkSettings { Enabled = [BenchmarkKind.CpuSingle], Runs = 1, CpuSingleRun = TimeSpan.FromMilliseconds(50) };
        var run = await runner.RunAsync(BenchmarkPhase.Before, settings, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(45, run.Conditions.PerformanceLimitPercent);
        Assert.Equal("unknown", run.Conditions.PerformanceLimitPowerSource);
        Assert.Equal(99, run.Conditions.AcMaxProcessorStatePercent);
        Assert.True(run.Conditions.DischargingOnAc);

        // CPU tests off -> sampler never runs, PerformanceLimitPercent stays null.
        var noCpuProbes = new FakeProbes(startCond, new Queue<PerformanceLimitSample?>([new(40, "ac")]));
        var noCpuRunner = new BenchmarkRunner(noCpuProbes, delay: (_, _) => Task.CompletedTask);
        var noCpuSettings = new BenchmarkSettings { Enabled = [BenchmarkKind.DnsLookup], Runs = 1 };
        var noCpuRun = await noCpuRunner.RunAsync(BenchmarkPhase.Before, noCpuSettings, null, null, TestContext.Current.CancellationToken);
        Assert.Equal(0, noCpuProbes.PerfLimitReads);
        Assert.Null(noCpuRun.Conditions.PerformanceLimitPercent);
        Assert.Null(noCpuRun.Conditions.PerformanceLimitPowerSource);

        // Upload & AgentExports include all new fields.
        var upload = BenchmarkUpload.Build(run, "pc-1", "LAPTOP3", new BenchmarkHardware());
        Assert.NotNull(upload);
        Assert.Equal(45, upload!.Conditions.PerformanceLimitPercent);
        Assert.Equal("unknown", upload.Conditions.PerformanceLimitPowerSource);
        Assert.Equal(99, upload.Conditions.AcMaxProcessorStatePercent);
        Assert.True(upload.Conditions.DischargingOnAc);

        var exportJson = JsonSerializer.Serialize(AgentExports.BuildBenchmark(settings, run, null, new BenchmarkComparison([], null, []), null, false, null, false, false, null));
        Assert.Contains("performanceLimitPercent", exportJson);
        Assert.Contains("performanceLimitPowerSource", exportJson);
        Assert.Contains("acMaxProcessorStatePercent", exportJson);
        Assert.Contains("dischargingOnAc", exportJson);
    }
}
