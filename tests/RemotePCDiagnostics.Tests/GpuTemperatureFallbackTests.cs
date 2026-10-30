using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeGpuTempSource(string name, Func<IReadOnlyList<GpuTemperatureSample>> read) : IGpuTemperatureSource
{
    public int Calls;
    public string Name => name;
    public IReadOnlyList<GpuTemperatureSample> Read() { Calls++; return read(); }
    public static FakeGpuTempSource Of(string name, params (string Adapter, double? C)[] v) => new(name, () => v.Select(x => new GpuTemperatureSample(x.Adapter, x.C)).ToList());
}

public class GpuTemperatureFallbackTests
{
    private const string Radeon = "AMD Radeon(TM) Graphics";
    private static SensorReading Gpu(double? v, string sensor = "GPU Core") => new(Radeon, HardwareKind.Gpu, sensor, SensorKind.Temperature, v, v, v, "°C");
    private static SensorReading Cpu(double v) => new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, v, v, v, "°C");

    [Fact]
    public void NotUsed_WhenLhmHasValidGpuTemperature()
    {
        var src = FakeGpuTempSource.Of("win", (Radeon, 55));
        var list = GpuTemperatureFallback.Apply([Cpu(60), Gpu(48)], [src]);
        Assert.DoesNotContain(list, r => r.IsFromWindows);
        Assert.Equal(0, src.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0.0)]
    [InlineData(double.NaN)]
    public void Used_WhenLhmGpuTemperatureIsInvalid(double? lhm)
    {
        var list = GpuTemperatureFallback.Apply([Cpu(60), Gpu(lhm)], [FakeGpuTempSource.Of("win", (Radeon, 52.3))]);
        var r = Assert.Single(list, x => x.IsFromWindows);
        Assert.Equal(52.3, r.Value);
    }

    [Fact]
    public void LimitSensorsDoNotCountAsValidGpuTemperature()
    {
        var list = GpuTemperatureFallback.Apply([Gpu(95, "GPU Critical Temperature")], [FakeGpuTempSource.Of("win", (Radeon, 50))]);
        Assert.Single(list, x => x.IsFromWindows);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0.0)]
    [InlineData(-5.0)]
    [InlineData(double.NaN)]
    [InlineData(500.0)]
    public void InvalidSourceValues_Ignored(double? v)
    {
        var list = GpuTemperatureFallback.Apply([Cpu(60)], [FakeGpuTempSource.Of("win", (Radeon, v))]);
        Assert.DoesNotContain(list, x => x.IsFromWindows);
    }

    [Fact]
    public void Naming_Flagging_AndThreshold()
    {
        var r = Assert.Single(GpuTemperatureFallback.Apply([], [FakeGpuTempSource.Of("win", (Radeon, 70))]));
        Assert.Equal("GPU temperature (from Windows)", r.SensorName);
        Assert.Equal("GPU temperature (from Windows)", r.FriendlyName);
        Assert.Equal(HardwareKind.Gpu, r.HardwareType);
        Assert.Equal(Radeon, r.HardwareName);
        Assert.True(r.IsFromWindows);
        Assert.False(r.IsApproximate);
        Assert.Same(SensorThresholds.WindowsGpu, SensorThresholds.For(r));
        Assert.Equal(SensorLevel.Ok, SensorThresholds.Evaluate(r));
        Assert.Equal(SensorLevel.Warning, SensorThresholds.Evaluate(r with { Value = 85 }));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(r with { Value = 95 }));
        var group = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot([r], true)).Groups.Single(g => g.Id == "gpu");
        Assert.Equal(70, group.Hottest);
    }

    [Fact]
    public void SourceOrdering_FirstValidWins_FailuresAndEmptySkipped()
    {
        var logs = new List<string>();
        var broken = new FakeGpuTempSource("broken", () => throw new InvalidOperationException("boom"));
        var empty = FakeGpuTempSource.Of("empty", (Radeon, 0));
        var good = FakeGpuTempSource.Of("good", (Radeon, 61));
        var later = FakeGpuTempSource.Of("later", (Radeon, 99));
        var list = GpuTemperatureFallback.Apply([], [broken, empty, good, later], logs.Add);
        Assert.Equal(61, Assert.Single(list).Value);
        Assert.Equal(0, later.Calls);
        Assert.Contains(logs, l => l.Contains("broken failed: boom"));
        Assert.Contains(logs, l => l.Contains("using good"));
    }

    [Fact]
    public void NoSources_OrNothingValid_LeavesListUnchanged()
    {
        Assert.Single(GpuTemperatureFallback.Apply([Cpu(60)], null));
        var logs = new List<string>();
        Assert.Single(GpuTemperatureFallback.Apply([Cpu(60)], [FakeGpuTempSource.Of("x")], logs.Add));
        Assert.Contains(logs, l => l.Contains("no source"));
    }

    private static SensorSnapshot Snap(double winGpu) =>
        new(GpuTemperatureFallback.Apply([Cpu(60), Gpu(0)], [FakeGpuTempSource.Of("win", (Radeon, winGpu))]), true);

    private static GpuStressOptions Opts() => new() { Duration = TimeSpan.FromMinutes(1), Gap = TimeSpan.FromSeconds(1), SensorInterval = TimeSpan.Zero };

    [Fact]
    public async Task StressTest_ReadsFallbackTemperature_AndAbortsWhenCritical()
    {
        var sensors = new SequenceSensorProvider(n => Snap(n >= 5 ? 96 : 70));
        var r = await new GpuStressTest(FakeGpuFactory.With(new FakeGpuDevice()), sensors, new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Overheated, r.Outcome);
    }

    [Fact]
    public async Task StressTest_FallbackBelowCritical_DoesNotAbort()
    {
        var sensors = new SequenceSensorProvider(_ => Snap(75));
        var r = await new GpuStressTest(FakeGpuFactory.With(new FakeGpuDevice()), sensors, new FakeStressClock()).RunAsync(Opts());
        Assert.NotEqual(GpuStressOutcome.Overheated, r.Outcome);
    }

    [Fact]
    public void TimeoutGpuTemperatureSource_ClearsFaultedPendingTask_AndRecovers()
    {
        int calls = 0;
        var inner = new FakeGpuTempSource("flaky", () => ++calls == 1 ? throw new InvalidOperationException("transient") : [new(Radeon, 58)]);
        var wrapped = new TimeoutGpuTemperatureSource(inner, TimeSpan.FromSeconds(2));
        Assert.Throws<AggregateException>(() => _ = wrapped.Read());
        var res = wrapped.Read();
        Assert.Equal(58, Assert.Single(res).Celsius);
    }
}

public class CpuTemperatureFallbackTests
{
    private const string Apu = "AMD Ryzen 7 5700U with Radeon Graphics";
    private static SensorReading Cpu(double? v) => new(Apu, HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, v, v, v, "°C");
    private static SensorReading WinGpu(double v) => new("AMD Radeon(TM) Graphics", HardwareKind.Gpu, GpuTemperatureFallback.SensorName, SensorKind.Temperature, v, null, null, "°C");
    private sealed class Zones(params double[] v) : IThermalZoneReader { public IReadOnlyList<double> ReadTenthsKelvin() => v; }

    [Fact]
    public void ApuDie_UsedOnlyWithoutRealCpuTemp_AndIsApproximate()
    {
        var list = CpuTemperatureFallback.ApplyApuDie([Cpu(0), WinGpu(57)], Apu);
        var r = Assert.Single(list, x => x.HardwareType == HardwareKind.Cpu && x.IsLive);
        Assert.Equal(57, r.Value);
        Assert.True(r.IsApproximate);
        Assert.Equal("CPU temperature (approximate, from built-in graphics)", r.FriendlyName);
        Assert.Null(SensorThresholds.For(r)); // approximate: no alert threshold, never aborts a stress test
        Assert.DoesNotContain(CpuTemperatureFallback.ApplyApuDie([Cpu(62), WinGpu(57)], Apu), x => x.IsApproximate);
    }

    [Theory]
    [InlineData("Intel Core i7-1165G7")]
    [InlineData("AMD Ryzen 9 7950X")]
    [InlineData(null)]
    public void ApuDie_NotUsedForNonApu(string? cpu) =>
        Assert.DoesNotContain(CpuTemperatureFallback.ApplyApuDie([WinGpu(57)], cpu), x => x.HardwareType == HardwareKind.Cpu);

    [Fact]
    public void Ordering_ApuBeforeThermalZone_ThermalZoneLastResort()
    {
        var withApu = ThermalZoneFallback.Apply(CpuTemperatureFallback.ApplyApuDie([WinGpu(57)], Apu), new Zones(3231.5));
        Assert.Single(withApu, x => x.HardwareType == HardwareKind.Cpu);
        Assert.DoesNotContain(withApu, x => x.HardwareName == ThermalZoneFallback.HardwareName);
        var noGpu = ThermalZoneFallback.Apply(CpuTemperatureFallback.ApplyApuDie([], Apu), new Zones(3231.5));
        Assert.Single(noGpu, x => x.HardwareName == ThermalZoneFallback.HardwareName);
    }

    [Fact]
    public void DriverNote_OnlyWithoutRealCpuTemp()
    {
        Assert.Equal(CpuTemperatureFallback.DriverMissingNote, CpuTemperatureFallback.Note([Cpu(0)], false));
        Assert.Equal(CpuTemperatureFallback.DriverMissingNote, CpuTemperatureFallback.Note(CpuTemperatureFallback.ApplyApuDie([WinGpu(50)], Apu), true));
        Assert.Null(CpuTemperatureFallback.Note([Cpu(55)], false));
        Assert.DoesNotContain("PawnIO", CpuTemperatureFallback.DriverMissingNote);
    }
}
