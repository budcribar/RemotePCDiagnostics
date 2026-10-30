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
        Assert.DoesNotContain("0°C", r.Message);
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
