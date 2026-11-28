using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Battery;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Tests.Replay;

namespace RemotePCDiagnostics.Tests.Battery;

/// <summary>The battery condition test (RPCD #281): fault states, the charging check, calibration, several batteries.</summary>
public sealed class BatteryConditionTests
{
    private static BatteryStatus Bat(int? percent = 60, bool? online = true, bool? charging = false, bool? discharging = false,
        int? chargeRate = null, int? dischargeRate = null, int design = 50000, int full = 45000) =>
        new("BAT1", "Sunwoda", "LiP", online == true ? "AC Power" : "Battery Power", percent, design, full, 120,
            PowerOnline: online, IsCharging: charging, IsDischarging: discharging, DischargeRateMw: dischargeRate, ChargeRateMw: chargeRate)
        {
            InstanceName = @"ACPI\PNP0C0A\1_0",
            RemainingMwh = percent is { } p ? full * p / 100 : null,
            ReportedFullChargeMwh = full,
        };

    private sealed class Source(params IReadOnlyList<BatteryStatus>[] readings) : IBatteryPowerSource
    {
        private int _next;
        public int Reads => _next;
        public IReadOnlyList<HpBatterySetting> Hp { get; init; } = [];
        public Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<BatteryStatus>?>(readings[Math.Min(_next++, readings.Length - 1)]);
        public Task<string?> ReadActivePlanAsync(CancellationToken ct) => Task.FromResult<string?>("Balanced");
        public Task<IReadOnlyList<HpBatterySetting>> ReadHpChargeSettingsAsync(CancellationToken ct) => Task.FromResult(Hp);
    }

    private static async Task<(AreaReport Report, List<TimeSpan> Waits)> Run(IBatteryPowerSource source, IHistoryStore? history = null)
    {
        var waits = new List<TimeSpan>();
        var module = new BatteryPowerModule(source, delay: (d, _) => { waits.Add(d); return Task.CompletedTask; }, history: history);
        var r = await module.RefreshAsync(null, TestContext.Current.CancellationToken);
        return ((AreaReport)r.Payload!, waits);
    }

    private static string? Row(AreaCard card, string label) => card.Rows.FirstOrDefault(r => r.Values[0] == label)?.Values[1];

    // Fault states

    [Fact]
    public void HealthyReading_HasNoFaults() => Assert.Empty(BatteryCondition.Faults(Bat() with { VoltageMv = 12100, DesignVoltageMv = 11550, Critical = false, DeviceStatus = "OK" }));

    [Theory]
    [InlineData("Pred Fail", AreaLevel.Error)]
    [InlineData("Error", AreaLevel.Error)]
    [InlineData("Degraded", AreaLevel.Warning)]
    public void WindowsBatteryStatus(string status, AreaLevel level) =>
        Assert.Equal(level, Assert.Single(BatteryCondition.Faults(Bat() with { DeviceStatus = status })).Level);

    [Fact]
    public void Critical_WithChargeLeft_Fails_ButWhenNearlyEmpty_IsAChargeAndRetest()
    {
        Assert.Equal(AreaLevel.Error, Assert.Single(BatteryCondition.Faults(Bat(percent: 60) with { Critical = true })).Level);
        var low = Assert.Single(BatteryCondition.Faults(Bat(percent: 4) with { Critical = true }));
        Assert.Equal(AreaLevel.Warning, low.Level);
        Assert.Equal(BatteryCondition.ChargeForAnHour, low.Advice);
    }

    [Fact]
    public void ImpossibleChargeStates_Fail()
    {
        Assert.Contains(BatteryCondition.Faults(Bat(charging: true, discharging: true)), f => f.Label == "Charge state" && f.Level == AreaLevel.Error);
        Assert.Contains(BatteryCondition.Faults(Bat(online: false, charging: true)), f => f.Label == "Charge state" && f.Level == AreaLevel.Error);
    }

    [Theory]
    [InlineData(30.0, null)]
    [InlineData(48.0, AreaLevel.Warning)]
    [InlineData(63.5, AreaLevel.Error)]
    [InlineData(-5.0, AreaLevel.Warning)]
    public void Temperature(double c, AreaLevel? level)
    {
        var f = BatteryCondition.Faults(Bat() with { TemperatureC = c }).SingleOrDefault(x => x.Label == "Temperature");
        Assert.Equal(level, f?.Level);
    }

    [Fact]
    public void Voltage_OutsideDesignRange_Fails()
    {
        Assert.Contains(BatteryCondition.Faults(Bat() with { VoltageMv = 8000, DesignVoltageMv = 11550 }), f => f.Label == "Voltage" && f.Level == AreaLevel.Error);
        Assert.Contains(BatteryCondition.Faults(Bat() with { VoltageMv = 14500, DesignVoltageMv = 11550 }), f => f.Label == "Voltage" && f.Level == AreaLevel.Error);
        Assert.Empty(BatteryCondition.Faults(Bat() with { VoltageMv = 13100, DesignVoltageMv = 11550 }));
    }

    [Fact]
    public void DeepDischarge_IsItsOwnFault_NotAlsoLowVoltage()
    {
        var faults = BatteryCondition.Faults(Bat(percent: 1) with { VoltageMv = 8200, DesignVoltageMv = 11550 });
        var f = Assert.Single(faults);
        Assert.Equal("Deep discharge", f.Label);
        Assert.Equal(AreaLevel.Error, f.Level);
    }

    [Fact]
    public void CorruptCapacity_ZeroOrAboveDesign_Fails()
    {
        Assert.Contains(BatteryCondition.Faults(Bat() with { ReportedFullChargeMwh = 0, MaxCapacity = null }), f => f.Label == "Capacity data");
        Assert.Contains(BatteryCondition.Faults(Bat(design: 50000, full: 61000)), f => f.Label == "Capacity data");
        Assert.DoesNotContain(BatteryCondition.Faults(Bat(design: 50000, full: 52000)), f => f.Label == "Capacity data");
        // Unknown (0xFFFFFFFF) is not corrupt: it's not reported.
        Assert.Empty(BatteryCondition.Faults(Bat() with { ReportedFullChargeMwh = BatteryReader.UnknownCapacity, MaxCapacity = null }));
    }

    [Fact]
    public async Task Fault_SeenOnlyOnce_IsAGlitch()
    {
        var src = new Source([Bat(percent: 70) with { Critical = true }], [Bat(percent: 70) with { Critical = false }]);
        var (report, waits) = await Run(src);
        Assert.Equal([BatteryPowerModule.ConfirmationDelay], waits);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.NotEqual(AreaLevel.Error, card.Level);
        Assert.Equal("None reported", Row(card, "Fault states"));
    }

    [Fact]
    public async Task Fault_InBothReadings_FailsTheCheck_WithItsRowAndAdvice()
    {
        var bad = Bat(percent: 70) with { Critical = true };
        var (report, _) = await Run(new Source([bad], [bad]));
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal("Battery reports a critical state at 70% charge", card.Headline);
        Assert.Contains("replace", card.Note);
        Assert.StartsWith("Battery reports a critical state", report.Summary);
    }

    // Charging check

    [Fact]
    public async Task OnAc_Low_NotCharging_WatchesThenFails()
    {
        var stuck = Bat(percent: 30);
        var src = new Source([stuck]);
        var (report, waits) = await Run(src);
        Assert.Equal(9, waits.Count(w => w == BatteryCondition.ChargeSampleEvery));
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal("Plugged in, but not charging", card.Headline);
        Assert.Equal("Not charging: stayed at 30% for 90 s while plugged in", Row(card, "Charging check"));
    }

    [Fact]
    public async Task OnAc_Low_StartsCharging_StopsWatchingEarly()
    {
        var src = new Source([Bat(percent: 30)], [Bat(percent: 30)], [Bat(percent: 31)]);
        var (report, waits) = await Run(src);
        Assert.Equal(2, waits.Count);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Equal("Charging: 30% to 31% in 20 s", Row(card, "Charging check"));
        Assert.Equal("31%", Row(card, "Current charge"));
    }

    [Fact]
    public async Task ChargeRate_ProvesChargingWithoutWaiting()
    {
        var (report, waits) = await Run(new Source([Bat(percent: 30, charging: true, chargeRate: 25000)]));
        Assert.Empty(waits);
        Assert.Equal("Charging at 25.0 W", Row(report.Cards.Single(c => c.Id == "battery"), "Charging check"));
    }

    [Fact]
    public async Task HoldingAboveHalf_WithNoKnownLimit_IsNotAFailure_AndIsNotWatched()
    {
        var (report, waits) = await Run(new Source([Bat(percent: 80)]));
        Assert.Empty(waits);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal("Holding at 80% while plugged in (a charge limit may be set)", Row(card, "Charging check"));
        Assert.Contains("Conservation mode", card.Note);
    }

    [Fact]
    public async Task HpChargeLimit_IsRespected_AndBelowItNotChargingFails()
    {
        var limited = new[] { new HpBatterySetting(HpBatteryCharge.CareFunction, "80%", ["100%", "80%", "50%"]) };
        var (at, _) = await Run(new Source([Bat(percent: 79)]) { Hp = limited });
        Assert.Equal("Held at the 80% charge limit (79%)", Row(at.Cards.Single(c => c.Id == "battery"), "Charging check"));
        Assert.Equal(DiagnosticStatus.Ok, at.Status);

        var (below, waits) = await Run(new Source([Bat(percent: 60)]) { Hp = limited });
        Assert.NotEmpty(waits);
        Assert.Equal(DiagnosticStatus.Error, below.Status);
    }

    [Fact]
    public void ChargeLimitPercent_FromHpSettings()
    {
        Assert.Equal(80, BatteryCondition.ChargeLimitPercent([new(HpBatteryCharge.HealthManager, "Maximize my battery health", ["Let HP manage my battery charging", "Maximize my battery health"])]));
        Assert.Equal(50, BatteryCondition.ChargeLimitPercent([new(HpBatteryCharge.CareFunction, "50%", ["100%", "80%", "50%"])]));
        Assert.Null(BatteryCondition.ChargeLimitPercent([new(HpBatteryCharge.CareFunction, "100%", ["100%", "80%"])]));
        Assert.Null(BatteryCondition.ChargeLimitPercent([]));
    }

    [Fact]
    public async Task FullyCharged_And_OnBattery_AreFine()
    {
        var (full, w1) = await Run(new Source([Bat(percent: 100)]));
        Assert.Empty(w1);
        Assert.Equal("Fully charged (100%)", Row(full.Cards.Single(c => c.Id == "battery"), "Charging check"));

        var (onBattery, w2) = await Run(new Source([Bat(percent: 40, online: false, discharging: true, dischargeRate: 7300)]));
        Assert.Empty(w2);
        Assert.Equal("Running on battery, using 7.3 W", Row(onBattery.Cards.Single(c => c.Id == "battery"), "Charging check"));
        Assert.Equal(DiagnosticStatus.Ok, onBattery.Status);
    }

    [Fact]
    public async Task UnpluggedDuringTheWatch_StopsWatching()
    {
        var src = new Source([Bat(percent: 30)], [Bat(percent: 30, online: false, discharging: true, dischargeRate: 6000)]);
        var (report, waits) = await Run(src);
        Assert.Single(waits);
        Assert.StartsWith("Running on battery", Row(report.Cards.Single(c => c.Id == "battery"), "Charging check"));
    }

    [Fact]
    public async Task Cancelling_StopsTheWatch()
    {
        using var cts = new CancellationTokenSource();
        var module = new BatteryPowerModule(new Source([Bat(percent: 20)]), delay: (_, ct) => { cts.Cancel(); return Task.Delay(Timeout.Infinite, ct); });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => module.RefreshAsync(null, cts.Token));
    }

    // Calibration

    [Fact]
    public void Calibration_WhenWindowsAndCapacityDisagree()
    {
        var f = BatteryCondition.Calibration(Bat(percent: 60) with { WindowsPercent = 85 });
        Assert.NotNull(f);
        Assert.Equal(AreaLevel.Warning, f.Level);
        Assert.Equal(BatteryCondition.Calibrate, f.Advice);
        Assert.Null(BatteryCondition.Calibration(Bat(percent: 60) with { WindowsPercent = 64 }));
    }

    [Fact]
    public void Calibration_WhenCapacityJumpsSinceTheLastRun()
    {
        var when = DateTimeOffset.UtcNow.AddDays(-7);
        Assert.NotNull(BatteryCondition.Calibration(Bat(full: 45000), new PreviousCapacity(38000, when)));
        Assert.Null(BatteryCondition.Calibration(Bat(full: 45000), new PreviousCapacity(44000, when)));
    }

    [Fact]
    public async Task Calibration_FromHistory_IsAWarningRow()
    {
        var past = new HistoryEntry(DateTimeOffset.UtcNow.AddDays(-3), "BatteryPower", "BatteryPower", "Ok", "", null, null, [], "PC", "1")
        {
            ModuleId = ModuleIds.BatteryPower,
            KeyMetrics = [new("battery.capacity", "Full charge capacity", 52000, "mWh")],
        };
        var (report, _) = await Run(new Source([Bat(percent: 100, full: 45000)]), new FixedHistory([past]));
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.StartsWith("Calibration needed: full charge capacity went from 52,000 to 45,000 mWh", Row(card, "Calibration"));
    }

    [Fact]
    public void PreviousCapacities_ReadsTheCheckAndTheScheduledPass()
    {
        HistoryEntry E(int daysAgo, string? instance, string id, double v) =>
            new(DateTimeOffset.UtcNow.AddDays(-daysAgo), "BatteryPower", "BatteryPower", "Ok", "", null, null, [], "PC", "1")
            { ModuleId = ModuleIds.BatteryPower, InstanceId = instance, KeyMetrics = [new(id, id, v, "mWh")] };
        var prev = BatteryCondition.PreviousCapacities(
            [E(1, "battery-1", "battery.capacity", 30000), E(2, null, "battery.capacity", 41000), E(3, null, "battery2.capacity", 29000)],
            2, DateTimeOffset.UtcNow);
        Assert.Equal(41000, prev[0]!.Mwh);
        Assert.Equal(30000, prev[1]!.Mwh);
    }

    private sealed class FixedHistory(IReadOnlyList<HistoryEntry> entries) : IHistoryStore
    {
        public HistoryReadResult Read(TimeSpan? within) => new(entries, true);
    }

    // Several batteries

    [Fact]
    public async Task TwoBatteries_OneCardEach_WithTheirOwnMetrics()
    {
        var b1 = Bat(percent: 100);
        var b2 = Bat(percent: 100, full: 30000) with { InstanceName = @"ACPI\PNP0C0A\2_0", Model = "BAT2" };
        var (report, _) = await Run(new Source([b1, b2]));
        Assert.Equal(["battery", "battery-2"], report.Cards.Where(c => c.Id.StartsWith("battery")).Select(c => c.Id));
        Assert.Equal("Battery 2 health", report.Cards.Single(c => c.Id == "battery-2").Title);
        Assert.StartsWith("Secondary", report.Cards.Single(c => c.Id == "battery-2").Meta);
        Assert.Contains(report.KeyMetrics!, m => m.Id == "battery.health" && m.Value == 90);
        Assert.Contains(report.KeyMetrics!, m => m.Id == "battery2.health" && m.Value == 60);
        Assert.Equal(DiagnosticStatus.Warning, report.Status); // the second one is worn
    }

    [Fact]
    public async Task FaultRetry_SingleUnconfirmedDischargingOnAc_DoesNotConfirmDrain()
    {
        var src = new Source([Bat(percent: 70) with { Critical = true }], [Bat(percent: 70, discharging: true)]);
        var (report, waits) = await Run(src);
        Assert.Equal([BatteryPowerModule.ConfirmationDelay], waits);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Null(Row(card, "Charger warning"));
        Assert.Equal("90% battery health", card.Headline);
        Assert.DoesNotContain("Plugged in, discharging", report.Summary);
    }

    [Fact]
    public async Task MidWatch_StartsDrainingOnAc_SurfacesWarning()
    {
        var src = new Source([Bat(percent: 30)], [Bat(percent: 30, discharging: true)]);
        var (report, waits) = await Run(src);
        Assert.Single(waits);
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("Draining while plugged in", Row(card, "Charging check"));
    }

    [Fact]
    public async Task TwoBatteries_WatchedBatteryStartsCharging_StopsEarlyEvenWhenOtherIsHeldBelowFull()
    {
        var b1Start = Bat(percent: 30);
        var b1Charging = Bat(percent: 31);
        var b2Held = Bat(percent: 80) with { InstanceName = @"ACPI\PNP0C0A\2_0", Model = "BAT2" };
        var (report, waits) = await Run(new Source([b1Start, b2Held], [b1Charging, b2Held]));
        Assert.Single(waits);
        Assert.Equal("Charging: 30% to 31% in 10 s", Row(report.Cards.Single(c => c.Id == "battery"), "Charging check"));
        Assert.Equal("Holding at 80% while plugged in (a charge limit may be set)", Row(report.Cards.Single(c => c.Id == "battery-2"), "Charging check"));
    }

    [Fact]
    public void JudgeCharging_RemainingMwhRisesWithoutPercentIncrease_FormatsMwh()
    {
        var samePct = BatteryCondition.JudgeCharging(
            Bat(percent: 30) with { RemainingMwh = 13500 },
            Bat(percent: 30) with { RemainingMwh = 13650 },
            TimeSpan.FromSeconds(10), null);
        Assert.Equal(ChargeOutcome.Charging, samePct.Outcome);
        Assert.Equal(AreaLevel.Ok, samePct.Level);
        Assert.Equal("Charging: 13,500 to 13,650 mWh in 10 s", samePct.Text);

        var nullPct = BatteryCondition.JudgeCharging(
            Bat(percent: null) with { RemainingMwh = 13500 },
            Bat(percent: null) with { RemainingMwh = 13650 },
            TimeSpan.FromSeconds(10), null);
        Assert.Equal(ChargeOutcome.Charging, nullPct.Outcome);
        Assert.Equal("Charging: 13,500 to 13,650 mWh in 10 s", nullPct.Text);
    }

    [Fact]
    public async Task TwoBatteries_SecondBatteryError_AppearsInReportSummary()
    {
        var b1 = Bat(percent: 100);
        var b2 = Bat(percent: 70) with { InstanceName = @"ACPI\PNP0C0A\2_0", Model = "BAT2", Critical = true };
        var (report, _) = await Run(new Source([b1, b2], [b1, b2]));
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.StartsWith("Battery reports a critical state at 70% charge", report.Summary);
    }

    // Identity and the reader

    [Fact]
    public void Reader_Conversions()
    {
        Assert.Equal(27.0, BatteryReader.Celsius(3001));
        Assert.Null(BatteryReader.Celsius(0));
        Assert.Null(BatteryReader.Celsius(4294967295));
        Assert.Equal("2023-01-15", BatteryReader.Date("20230115000000.000000-000"));
        Assert.Equal("2024-06-02", BatteryReader.Date("2024-06-02T00:00:00Z"));
        Assert.Equal("", BatteryReader.Date("00000000000000.000000-000"));
        Assert.Equal("", BatteryReader.Date(null));
        Assert.Equal(12142, BatteryReader.Millivolts(12142));
        Assert.Null(BatteryReader.Millivolts(4294967295));
    }

    private static MachineRecording Sample => RecordingLibrary.Load("sample/sample-laptop");

    private static async Task<AreaReport> Replay(MachineRecording rec) =>
        (AreaReport)(await new ReplayedPc(rec).BatteryPower().RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!;

    [Fact]
    public async Task Replay_ReadsVoltageSerialAndNoFaults()
    {
        var card = (await Replay(Sample)).Cards.Single(c => c.Id == "battery");
        Assert.Equal("12.82 V (design 11.55 V)", Row(card, "Voltage"));
        Assert.Equal("<serial:5a5a5a>", Row(card, "Serial number"));
        Assert.Equal("None reported", Row(card, "Fault states"));
        Assert.Equal("Fully charged (100%)", Row(card, "Charging check"));
    }

    [Fact]
    public async Task Replay_CriticalFlag_Fails()
    {
        var report = await Replay(Sample.SetWmi("Voltage, Critical FROM BatteryStatus", "Critical", true));
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Contains(report.Cards.Single(c => c.Id == "battery").Rows, r => r.Values[0] == "Critical state" && r.Level == AreaLevel.Error);
    }

    [Fact]
    public async Task Replay_PredFail_Fails()
    {
        var report = await Replay(Sample.SetWmi("FROM Win32_Battery", "Status", "Pred Fail"));
        Assert.Equal(DiagnosticStatus.Error, report.Status);
    }

    [Fact]
    public async Task Replay_HotBattery_IsTooHotToTest()
    {
        var rec = Sample.AddWmiRow("FROM BatteryTemperature", new Dictionary<string, object?> { ["InstanceName"] = @"ACPI\PNP0C0A\1_0", ["Temperature"] = 3221L });
        var card = (await Replay(rec)).Cards.Single(c => c.Id == "battery");
        Assert.Contains(card.Rows, r => r.Values.SequenceEqual(["Temperature", "Hot: 49 °C"]) && r.Level == AreaLevel.Warning);
        Assert.Contains(BatteryCondition.LetItCool, card.Note);
    }

    [Fact]
    public async Task Replay_OldRecording_WithoutTheNewAnswers_StillReads()
    {
        var rec = Sample.FailWmi("Voltage, Critical FROM", "InvalidClass (0x80041010)").FailWmi("SerialNumber", "Generic failure")
            .FailWmi("FROM BatteryTemperature", "InvalidClass (0x80041010)").FailWmi("FROM Win32_Battery", "InvalidClass (0x80041010)");
        var report = await Replay(rec);
        var card = report.Cards.Single(c => c.Id == "battery");
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Null(Row(card, "Voltage"));
        Assert.Null(Row(card, "Fault states"));
    }

    // The Agent's scheduled pass fails on the same faults

    [Fact]
    public async Task ScheduledPass_FailsOnAFault()
    {
        var rec = Sample.SetWmi("FROM Win32_Battery", "Status", "Pred Fail");
        var probes = new RemotePCDiagnostics.Core.Metrics.CoreMetricsProbes(null, null, wmi: new ReplayedPc(rec).Wmi);
        var results = await probes.MeasureAsync(ModuleSlugs.BatteryPower, TestContext.Current.CancellationToken);
        var r = Assert.Single(results);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains(((AreaReport)r.Payload!).KeyMetrics!, m => m.Id == "battery.health");
    }
}
