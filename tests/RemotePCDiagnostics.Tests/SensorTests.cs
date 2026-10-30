using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeSensorProvider(SensorSnapshot? snapshot, string? unavailable = null) : ISensorProvider
{
    public ModuleAvailability CheckAvailability() =>
        unavailable is null ? ModuleAvailability.Available : ModuleAvailability.Unavailable(unavailable);
    public SensorSnapshot Read() => snapshot ?? throw new InvalidOperationException("driver failed");
}

public class SensorThresholdTests
{
    private static SensorReading T(HardwareKind k, string hw, double? v, string sensor = "Package") =>
        new(hw, k, sensor, SensorKind.Temperature, v, v, v, "°C");

    [Theory]
    [InlineData("Intel Core i9-14900K", 89.9, SensorLevel.Ok)]
    [InlineData("Intel Core i9-14900K", 90, SensorLevel.Warning)]
    [InlineData("Intel Core i9-14900K", 98, SensorLevel.Critical)]
    [InlineData("AMD Ryzen 7 9700X", 84, SensorLevel.Ok)]
    [InlineData("AMD Ryzen 7 9700X", 85, SensorLevel.Warning)]
    [InlineData("AMD Ryzen 7 9700X", 93, SensorLevel.Critical)]
    [InlineData("Some Unknown CPU", 120, SensorLevel.Neutral)]
    public void Cpu(string hw, double v, SensorLevel expected) =>
        Assert.Equal(expected, SensorThresholds.Evaluate(T(HardwareKind.Cpu, hw, v)));

    [Fact]
    public void Gpu()
    {
        Assert.Equal(SensorLevel.Warning, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "NVIDIA GeForce RTX 4070", 83, "GPU Core")));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "NVIDIA GeForce RTX 4070", 88, "GPU Core")));
        Assert.Equal(SensorLevel.Ok, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "AMD Radeon RX 7900 XTX", 99, "GPU Hot Spot")));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "AMD Radeon RX 7900 XTX", 108, "GPU Hot Spot")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "AMD Radeon RX 7900 XTX", 108, "GPU Core"))); // edge: no published limit
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Gpu, "Intel Arc A770", 100, "GPU Core")));
    }

    [Fact]
    public void StorageBoardFansAndNulls()
    {
        Assert.Equal(SensorLevel.Warning, SensorThresholds.Evaluate(T(HardwareKind.Storage, "Samsung SSD 990 PRO 2TB", 65, "Temperature")));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(T(HardwareKind.Storage, "WD NVMe drive", 70, "Temperature")));
        Assert.Equal(SensorLevel.Warning, SensorThresholds.Evaluate(T(HardwareKind.Storage, "Seagate BarraCuda 2TB", 50, "Temperature")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Storage, "Generic Disk", 90, "Temperature")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Motherboard, "Nuvoton NCT6798D", 95, "VRM")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(new SensorReading("Nuvoton", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, 0, 0, 1200, "RPM")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Cpu, "Intel Core i9-14900K", null)));
    }
}

public class LibreHardwareMonitorModuleTests
{
    private static readonly SensorSnapshot Sample = new(
    [
        new("Intel Core i9-14900K", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, 55, 40, 80, "°C"),
        new("NVIDIA GeForce RTX 4070", HardwareKind.Gpu, "GPU Core", SensorKind.Temperature, 84, 35, 86, "°C"),
        new("Samsung SSD 990 PRO 2TB", HardwareKind.Storage, "Temperature", SensorKind.Temperature, 41, 30, 50, "°C"),
        new("Nuvoton NCT6798D", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, 950, 0, 1500, "RPM"),
        new("Nuvoton NCT6798D", HardwareKind.Motherboard, "Fan #2", SensorKind.Fan, 0, 0, 0, "RPM"),
    ], IsElevated: true);

    [Fact]
    public async Task Refresh_GroupsAndWorstLevelDrivesStatus()
    {
        var m = new LibreHardwareMonitorModule(new FakeSensorProvider(Sample));
        var r = Assert.IsType<DiagnosticResult<SensorReport>>(await m.RefreshAsync(null));
        Assert.Equal(DiagnosticStatus.Warning, r.Status); // GPU 84 >= 83
        var g = r.Data!.Groups.ToDictionary(x => x.Id);
        Assert.Equal(SensorLevel.Ok, g["cpu"].Level);
        Assert.Equal(SensorLevel.Warning, g["gpu"].Level);
        Assert.Equal(SensorLevel.Ok, g["storage"].Level);
        Assert.Equal(SensorLevel.Neutral, g["fans"].Level);
        Assert.Equal(2, g["fans"].Readings.Count);
        Assert.Contains("CPU 55°C", r.Message);
        Assert.Contains("2 fan(s)", r.Message);
    }

    [Fact]
    public async Task EmptyNotElevated_IsWarningWithAdminHint()
    {
        var m = new LibreHardwareMonitorModule(new FakeSensorProvider(new SensorSnapshot([], false)));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Contains("administrator", r.Message);
    }

    [Fact]
    public async Task Service_UnavailableProvider_IsError_AndRunAllIncludesModule()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new LibreHardwareMonitorModule(new FakeSensorProvider(null, "no driver")), new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        var results = await svc.RunAllAsync();
        Assert.Equal(2, results.Length);
        var r = store.Get(LibreHardwareMonitorModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("no driver", r.Message);
    }

    [Fact]
    public async Task Service_ProviderThrows_IsError()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new LibreHardwareMonitorModule(new FakeSensorProvider(null))]);
        var r = await svc.RunAsync(LibreHardwareMonitorModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Fact]
    public void Json_RoundTripsWithStringEnums()
    {
        var json = JsonSerializer.Serialize(Sample);
        Assert.Contains("\"HardwareType\":\"Cpu\"", json);
        Assert.Contains("\"SensorType\":\"Fan\"", json);
        var back = JsonSerializer.Deserialize<SensorSnapshot>(json)!;
        Assert.Equal(Sample.Readings, back.Readings);
        Assert.True(back.IsElevated);
    }
}

public class SensorNoDataTests
{
    private static SensorReading T(HardwareKind k, string n, double? v) => new("HW", k, n, SensorKind.Temperature, v, v, v, "°C");

    [Theory]
    [InlineData(0.0, false)]
    [InlineData(-5.0, false)]
    [InlineData(double.NaN, false)]
    [InlineData(45.0, true)]
    public void Temperature_ZeroOrInvalid_IsNoData(double v, bool expected) => Assert.Equal(expected, T(HardwareKind.Cpu, "Core", v).HasData);

    [Fact]
    public void Fan_ZeroRpm_IsData_NullIsNot()
    {
        Assert.True(new SensorReading("EC", HardwareKind.Controller, "Fan", SensorKind.Fan, 0, 0, 0, "RPM").HasData);
        Assert.False(new SensorReading("EC", HardwareKind.Controller, "Fan", SensorKind.Fan, null, null, null, "RPM").HasData);
    }

    [Fact]
    public async Task ZeroCpuTemp_ExcludedAndEmptyGroupsListedAsMissing()
    {
        var snap = new SensorSnapshot([T(HardwareKind.Cpu, "Core (Tctl/Tdie)", 0), T(HardwareKind.Storage, "Temperature", 40)], IsElevated: true);
        var m = new LibreHardwareMonitorModule(new FakeSensorProvider(snap));
        var r = Assert.IsType<DiagnosticResult<SensorReport>>(await m.RefreshAsync(null));
        var rep = r.Data!;
        Assert.Null(rep.Groups.First(g => g.Id == "cpu").Hottest);
        Assert.Contains("CPU —", r.Message);
        Assert.DoesNotContain("CPU 0°C", r.Message);
        Assert.Equal(["storage"], rep.VisibleGroups.Select(g => g.Id));
        Assert.Equal("Not reported by this PC: CPU temperatures, GPU temperatures, board and memory temperatures, fans", rep.MissingText);
    }

    [Fact]
    public void AllEmpty_NoMissingLine_FriendlyMessage()
    {
        var rep = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot([T(HardwareKind.Cpu, "Core", 0)], IsElevated: true));
        Assert.Empty(rep.VisibleGroups);
        Assert.Null(rep.MissingText);
        Assert.Equal("No temperature or fan sensors found", LibreHardwareMonitorModule.Summarize(rep));
    }

    [Fact]
    public void NothingMissing_NoMissingLine()
    {
        var rep = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot([
            T(HardwareKind.Cpu, "a", 50), T(HardwareKind.Gpu, "b", 50), T(HardwareKind.Storage, "c", 40), T(HardwareKind.Motherboard, "d", 40),
            new("EC", HardwareKind.Controller, "Fan", SensorKind.Fan, 0, 0, 0, "RPM")], IsElevated: true));
        Assert.Null(rep.MissingText);
        Assert.Equal(5, rep.VisibleGroups.Count);
    }
}

public class SensorFriendlyNameTests
{
    private static SensorReading D(string n, double v) => new("SAMSUNG MZAL8512HDLU-00BL2", HardwareKind.Storage, n, SensorKind.Temperature, v, v, v, "°C");

    [Theory]
    [InlineData("Composite Temperature", "Drive temperature (overall)")]
    [InlineData("Temperature #1", "Drive temperature, sensor 1")]
    [InlineData("Temperature #2", "Drive temperature, sensor 2")]
    [InlineData("Warning Temperature", "Drive warning limit")]
    [InlineData("Critical Temperature", "Drive critical limit")]
    public void StorageNames_AreFriendly(string raw, string friendly) => Assert.Equal(friendly, D(raw, 50).FriendlyName);

    [Fact]
    public void DeviceLabel_IncludesType() => Assert.Equal("Drive: SAMSUNG MZAL8512HDLU-00BL2", D("Composite Temperature", 50).FriendlyDevice);

    [Fact]
    public void DriveLimits_ExcludedFromHottestAndStatus()
    {
        var rep = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(
            [D("Composite Temperature", 50), D("Temperature #1", 48), D("Warning Temperature", 82), D("Critical Temperature", 84)], IsElevated: true));
        var g = rep.Groups.First(x => x.Id == "storage");
        Assert.Equal(50, g.Hottest);
        Assert.True(D("Critical Temperature", 84).IsLimit);
        Assert.False(D("Critical Temperature", 84).IsLive);
        Assert.All(g.Readings.Where(r => r.Reading.IsLimit), r => Assert.Equal(SensorLevel.Neutral, r.Level));
        Assert.NotEqual(SensorLevel.Critical, rep.Level);
    }
}

public class SensorSignatureTests
{
    private static SensorReport R(double v) => LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(
        [new("CPU", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, v, v, v, "°C")], IsElevated: true));

    [Fact]
    public void Signature_SameValues_Equal_ChangedValue_Differs()
    {
        Assert.Equal(SensorReport.Signature("Ok", "m", R(50)), SensorReport.Signature("Ok", "m", R(50)));
        Assert.NotEqual(SensorReport.Signature("Ok", "m", R(50)), SensorReport.Signature("Ok", "m", R(51)));
        Assert.NotEqual(SensorReport.Signature("Ok", "m", R(50)), SensorReport.Signature("Warning", "m", R(50)));
    }
}

public class ThermalZoneFallbackTests
{
    private sealed class Zones(params double[] v) : IThermalZoneReader { public IReadOnlyList<double> ReadTenthsKelvin() => v; }
    private sealed class Broken : IThermalZoneReader { public IReadOnlyList<double> ReadTenthsKelvin() => throw new InvalidOperationException("no wmi"); }
    private static SensorReading Cpu(double v) => new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, v, v, v, "°C");

    [Theory]
    [InlineData(3232, 50.0)]
    [InlineData(0, null)]
    [InlineData(2731, null)]   // ~0 °C: implausible
    [InlineData(4500, null)]   // ~177 °C: implausible
    public void ToCelsius(double raw, double? expected) => Assert.Equal(expected, ThermalZoneFallback.ToCelsius(raw));

    [Fact]
    public void UsedOnlyWhenNoRealCpuTemp()
    {
        var withZero = ThermalZoneFallback.Apply([Cpu(0)], new Zones(3132, 3232));
        var fb = Assert.Single(withZero, r => r.IsApproximate);
        Assert.Equal(50.0, fb.Value);
        Assert.Equal("CPU/system temperature (approximate)", fb.FriendlyName);
        Assert.DoesNotContain(ThermalZoneFallback.Apply([Cpu(61)], new Zones(3232)), r => r.IsApproximate);
        Assert.DoesNotContain(ThermalZoneFallback.Apply([], new Zones(0)), r => r.IsApproximate);
        Assert.Empty(ThermalZoneFallback.Apply([], new Broken()));
    }

    [Fact]
    public void Approximate_FeedsCpuCard_ButNeverCritical()
    {
        var rep = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(ThermalZoneFallback.Apply([Cpu(0)], new Zones(3982)), true)); // 125 -> no; use 3972 ~124
        var rep2 = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(ThermalZoneFallback.Apply([Cpu(0)], new Zones(3732)), true)); // 100 °C
        Assert.Null(rep.Groups.First(g => g.Id == "cpu").Hottest);
        Assert.Equal(100.0, rep2.Groups.First(g => g.Id == "cpu").Hottest);
        Assert.Equal(SensorLevel.Neutral, rep2.Level);
    }
}
