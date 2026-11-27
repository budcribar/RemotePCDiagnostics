using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
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
        Assert.Equal(SensorLevel.Ok, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 50, "Composite Temperature")));
        Assert.Equal(SensorLevel.Warning, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 65, "Composite Temperature")));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 70, "Composite Temperature")));
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 70, "Temperature")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 75, "Temperature #1")));
        Assert.Equal(SensorLevel.Neutral, SensorThresholds.Evaluate(T(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU-00BL2", 84, "Critical Temperature")));
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
        Assert.Contains("2 fans", r.Message);
    }

    [Fact]
    public void Summarize_WhenElevatedAndZeroFans_OmitsFanSpeedWithoutAdminWarning()
    {
        var snapshot = new SensorSnapshot([
            new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, 50, 40, 60, "°C"),
            new("AMD Radeon Graphics", HardwareKind.Gpu, "GPU Core", SensorKind.Temperature, 45, 35, 55, "°C"),
            new("Samsung SSD 990 PRO 2TB", HardwareKind.Storage, "Temperature", SensorKind.Temperature, 40, 30, 45, "°C"),
        ], IsElevated: true);

        var report = LibreHardwareMonitorModule.BuildReport(snapshot);
        var summary = LibreHardwareMonitorModule.Summarize(report);

        Assert.DoesNotContain("fan speed not reported", summary);
        Assert.DoesNotContain("administrator rights", summary);
        Assert.Equal("CPU 50°C · GPU 45°C · Storage 40°C", summary);
    }

    [Fact]
    public void Summarize_WhenNotElevatedAndZeroFans_AppendsAdminWarning()
    {
        var snapshot = new SensorSnapshot([
            new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, 50, 40, 60, "°C"),
            new("AMD Radeon Graphics", HardwareKind.Gpu, "GPU Core", SensorKind.Temperature, 45, 35, 55, "°C"),
            new("Samsung SSD 990 PRO 2TB", HardwareKind.Storage, "Temperature", SensorKind.Temperature, 40, 30, 45, "°C"),
        ], IsElevated: false);

        var report = LibreHardwareMonitorModule.BuildReport(snapshot);
        var summary = LibreHardwareMonitorModule.Summarize(report);

        Assert.DoesNotContain("fan speed not reported", summary);
        Assert.Contains("(some sensors need administrator rights)", summary);
        Assert.Equal("CPU 50°C · GPU 45°C · Storage 40°C (some sensors need administrator rights)", summary);
    }

    [Fact]
    public void Summarize_OmitsUnreadGpuAndFans()
    {
        var snapshot = new SensorSnapshot([
            new("Snapdragon X Elite", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, 65, 55, 70, "°C"),
            new("NVMe Drive", HardwareKind.Storage, "Composite Temperature", SensorKind.Temperature, 42, 38, 45, "°C"),
        ], IsElevated: true);

        var summary = LibreHardwareMonitorModule.Summarize(LibreHardwareMonitorModule.BuildReport(snapshot));

        Assert.Equal("CPU 65°C · Storage 42°C", summary);
        Assert.DoesNotContain("GPU", summary);
        Assert.DoesNotContain("—", summary);
        Assert.DoesNotContain("fan", summary, StringComparison.OrdinalIgnoreCase);
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

    // Issue #48: one NVMe drive, Composite 42 °C (what Windows / Drive health reports) and an internal sensor at 64 °C.
    [Fact]
    public void Summarize_StorageUsesDriveOverall_AndNamesHotterSensor()
    {
        var snapshot = new SensorSnapshot([
            new("SAMSUNG MZAL8512HDLU", HardwareKind.Storage, "Composite Temperature", SensorKind.Temperature, 42, 35, 45, "°C"),
            new("SAMSUNG MZAL8512HDLU", HardwareKind.Storage, "Temperature #1", SensorKind.Temperature, 42, 35, 45, "°C"),
            new("SAMSUNG MZAL8512HDLU", HardwareKind.Storage, "Temperature #2", SensorKind.Temperature, 64, 50, 66, "°C"),
            new("SAMSUNG MZAL8512HDLU", HardwareKind.Storage, "Critical Temperature", SensorKind.Temperature, 85, null, null, "°C"),
        ], IsElevated: true);
        var report = LibreHardwareMonitorModule.BuildReport(snapshot);
        Assert.Equal(42, LibreHardwareMonitorModule.DriveOverall(report.Groups.Single(g => g.Id == "storage").Readings.Select(r => r.Reading)));
        Assert.Contains("Storage 42°C (hottest sensor 64°C)", LibreHardwareMonitorModule.Summarize(report));
    }

    [Fact]
    public void Summarize_StorageWithoutComposite_UsesHottestAndNoSensorNote()
    {
        var snapshot = new SensorSnapshot([
            new("Drive A", HardwareKind.Storage, "Temperature #1", SensorKind.Temperature, 40, null, null, "°C"),
            new("Drive A", HardwareKind.Storage, "Temperature #2", SensorKind.Temperature, 43, null, null, "°C"),
            new("Drive B", HardwareKind.Storage, "Composite Temperature", SensorKind.Temperature, 38, null, null, "°C"),
        ], IsElevated: true);
        var summary = LibreHardwareMonitorModule.Summarize(LibreHardwareMonitorModule.BuildReport(snapshot));
        Assert.Equal("Storage 43°C", summary);
        Assert.DoesNotContain("hottest sensor", summary);
    }

    [Theory]
    [InlineData(1, 0, "1 fan")] [InlineData(1, 1, "1 fan, stopped")] [InlineData(3, 1, "3 fans, 1 stopped")]
    [InlineData(2, 2, "2 fans, stopped")] [InlineData(0, 0, "")]
    public void FansText_KeepsCountAndNamesStopped(int fans, int stopped, string expected) =>
        Assert.Equal(expected, LibreHardwareMonitorModule.FansText(fans, stopped));
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
        Assert.Equal("Storage 40°C", r.Message);
        Assert.DoesNotContain("CPU", r.Message);
        Assert.DoesNotContain("GPU", r.Message);
        Assert.Equal(["storage"], rep.VisibleGroups.Select(g => g.Id));
        Assert.Equal("Not reported by this PC: CPU temperatures, GPU temperatures, board and memory temperatures", rep.MissingText);
        Assert.DoesNotContain("fans", rep.VisibleGroups.Select(g => g.Id));
    }

    [Fact]
    public async Task AllEmpty_NoMissingLine_FriendlyMessage()
    {
        var raw = new SensorSnapshot([T(HardwareKind.Cpu, "Core", 0)], IsElevated: false);
        var rep = LibreHardwareMonitorModule.BuildReport(raw);
        Assert.Empty(rep.VisibleGroups);
        Assert.Null(rep.MissingText);
        Assert.Equal("No sensors found. " + RemotePCDiagnostics.Core.Session.ElevationService.AdminRepairHint, LibreHardwareMonitorModule.Summarize(rep));
        Assert.Equal(DiagnosticStatus.Warning, LibreHardwareMonitorModule.ToStatus(rep, raw));

        var refresh = await new LibreHardwareMonitorModule(new FakeSensorProvider(raw)).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, refresh.Status);
        Assert.Contains("administrator", refresh.Message);

        var elevatedRaw = new SensorSnapshot([T(HardwareKind.Cpu, "Core", 0)], IsElevated: true);
        var elevatedRep = LibreHardwareMonitorModule.BuildReport(elevatedRaw);
        Assert.Equal("No temperature or fan sensors found", LibreHardwareMonitorModule.Summarize(elevatedRep));
        Assert.Equal(DiagnosticStatus.Warning, LibreHardwareMonitorModule.ToStatus(elevatedRep, elevatedRaw));
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
        // Sanity check: on this OEM NVMe drive, 84 °C on Composite Temperature WOULD be Critical if not a limit sensor.
        Assert.Equal(SensorLevel.Critical, SensorThresholds.Evaluate(D("Composite Temperature", 84)));
        Assert.Equal(SensorLevel.Ok, SensorThresholds.Evaluate(D("Composite Temperature", 50)));

        var rep = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(
            [D("Composite Temperature", 50), D("Temperature #1", 48), D("Warning Temperature", 82), D("Critical Temperature", 84)], IsElevated: true));
        var g = rep.Groups.First(x => x.Id == "storage");
        Assert.Equal(50, g.Hottest);
        Assert.Equal(SensorLevel.Ok, g.Readings.Single(r => r.Reading.SensorName == "Composite Temperature").Level);
        Assert.True(D("Critical Temperature", 84).IsLimit);
        Assert.False(D("Critical Temperature", 84).IsLive);
        Assert.All(g.Readings.Where(r => r.Reading.IsLimit), r => Assert.Equal(SensorLevel.Neutral, r.Level));
        Assert.Equal(SensorLevel.Ok, rep.Level);
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
    [InlineData(3231.5, 50.0)]
    [InlineData(0, null)]
    [InlineData(2731, null)]   // ~0 °C: implausible
    [InlineData(4500, null)]   // ~177 °C: implausible
    public void ToCelsius(double raw, double? expected) => Assert.Equal(expected, ThermalZoneFallback.ToCelsius(raw));

    [Fact]
    public void UsedOnlyWhenNoRealCpuTemp()
    {
        var withZero = ThermalZoneFallback.Apply([Cpu(0)], new Zones(3131.5, 3231.5));
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
        var rep2 = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(ThermalZoneFallback.Apply([Cpu(0)], new Zones(3731.5)), true)); // 100 °C
        Assert.Null(rep.Groups.First(g => g.Id == "cpu").Hottest);
        Assert.Equal(100.0, rep2.Groups.First(g => g.Id == "cpu").Hottest);
        Assert.Equal(SensorLevel.Neutral, rep2.Level);
    }
}

public class LhmSensorProviderElevationTests
{
    private sealed class FakeElevatedBridge(bool isConnected, Func<CancellationToken, Task<SensorSnapshot?>>? onRead = null) : RemotePCDiagnostics.Core.Session.IElevatedCommandBridge
    {
        public bool IsConnected { get; set; } = isConnected;
        public int ReadCount { get; private set; }

        public Task<RemotePCDiagnostics.Core.Osquery.ProcessResult?> RunElevatedAsync(
            string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            throw new NotSupportedException();

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default)
        {
            ReadCount++;
            return onRead != null ? onRead(ct) : Task.FromResult<SensorSnapshot?>(null);
        }

        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    [Fact]
    public void Read_WhenElevatedBridgeConnected_ReturnsRemoteSnapshotAsElevated()
    {
        if (!OperatingSystem.IsWindows()) return;
        RunRemoteElevated();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void RunRemoteElevated()
    {
        var expectedReading = new SensorReading("Lenovo", HardwareKind.Controller, "Fan 1", SensorKind.Fan, 2500, 2000, 3000, "RPM");
        var remoteSnap = new SensorSnapshot([expectedReading], IsElevated: false, Note: "old note");

        var bridge = new FakeElevatedBridge(isConnected: true, _ => Task.FromResult<SensorSnapshot?>(remoteSnap));
        using var provider = new LhmSensorProvider(new NoEcFanSource(), elevatedBridge: bridge, isLocalProcessElevated: () => false);

        var result = provider.Read();

        Assert.Equal(1, bridge.ReadCount);
        Assert.True(result.IsElevated);
        Assert.Null(result.Note);
        Assert.Single(result.Readings);
        Assert.Equal(expectedReading, result.Readings[0]);
    }

    [Fact]
    public void Read_WhenElevatedBridgeConnected_AndRemoteFails_LocalFallbackHasElevatedTrue()
    {
        if (!OperatingSystem.IsWindows()) return;
        RunRemoteFallback();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void RunRemoteFallback()
    {
        var bridge = new FakeElevatedBridge(isConnected: true, _ => Task.FromException<SensorSnapshot?>(new IOException("pipe broken")));
        using var provider = new LhmSensorProvider(new NoEcFanSource(), elevatedBridge: bridge, isLocalProcessElevated: () => false);

        var result = provider.Read();

        Assert.Equal(1, bridge.ReadCount);
        Assert.True(result.IsElevated);
        Assert.Null(result.Note);
    }
}

public class LhmCpuSupportTests
{
    // LHM's CPU group executes x86 CPUID; on ARM64 (Snapdragon laptops) Computer.Open() throws an SEHException
    // and no sensor at all can be read, so the CPU group must stay off there.
    [Theory]
    [InlineData(System.Runtime.InteropServices.Architecture.X64, true)]
    [InlineData(System.Runtime.InteropServices.Architecture.X86, true)]
    [InlineData(System.Runtime.InteropServices.Architecture.Arm64, false)]
    [InlineData(System.Runtime.InteropServices.Architecture.Arm, false)]
    public void SupportsLhmCpu_OnlyOnX86AndX64(System.Runtime.InteropServices.Architecture arch, bool expected) =>
        Assert.Equal(expected, LhmSensorProvider.SupportsLhmCpu(arch));
}

public class OwnSensorSourcesTests
{
    private static SensorReading Temp(HardwareKind k, string hw, double v, string sensor = "Temperature") =>
        new(hw, k, sensor, SensorKind.Temperature, v, null, null, "°C");

    [Fact]
    public void Merge_KeepsOwnReadings_DropsLhmTemperaturesForTheSameDevice_KeepsTheRest()
    {
        var own = new List<SensorReading>
        {
            Temp(HardwareKind.Gpu, "NVIDIA GeForce RTX 4060 Laptop GPU", 55, GpuTemperatureFallback.SensorName),
            Temp(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU", 38),
        };
        var lhm = new List<SensorReading>
        {
            Temp(HardwareKind.Gpu, "NVIDIA NVIDIA GeForce RTX 4060 Laptop GPU", 54, "GPU Core"),      // same GPU, vendor prefix
            new("NVIDIA NVIDIA GeForce RTX 4060 Laptop GPU", HardwareKind.Gpu, "GPU Fan", SensorKind.Fan, 2100, null, null, "RPM"),
            Temp(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU", 37, "Composite Temperature"),
            Temp(HardwareKind.Storage, "SAMSUNG MZAL8512HDLU", 82, "Warning Temperature"),          // a limit, not a reading
            Temp(HardwareKind.Storage, "WD Blue SN580", 41),                                         // only LHM sees it
            Temp(HardwareKind.Cpu, "Intel Core i7-13700H", 70, "CPU Package"),                       // no reader of ours
        };

        var merged = OwnSensorSources.Merge(own, lhm);

        Assert.Equal(
            ["GPU temperature (from Windows)", "Temperature", "GPU Fan", "Warning Temperature", "Temperature", "CPU Package"],
            merged.Select(r => r.SensorName));
        Assert.DoesNotContain(merged, r => r.SensorName is "GPU Core" or "Composite Temperature");
        Assert.Contains(merged, r => r.HardwareName == "WD Blue SN580");
    }

    [Fact]
    public void Merge_WithNoOwnReadings_IsLhmUnchanged()
    {
        var lhm = new List<SensorReading> { Temp(HardwareKind.Cpu, "AMD Ryzen 5 7520U", 60, "Core (Tctl/Tdie)") };
        Assert.Equal(lhm, OwnSensorSources.Merge([], lhm));
    }

    [Theory]
    [InlineData("NVIDIA GeForce RTX 4060", "NVIDIA NVIDIA GeForce RTX 4060", true)]
    [InlineData("Samsung SSD 980", "samsung ssd 980", true)]
    [InlineData("Samsung SSD 980", "WD Blue SN580", false)]
    [InlineData("", "WD Blue SN580", false)]
    public void SameDevice(string a, string b, bool expected) => Assert.Equal(expected, OwnSensorSources.SameDevice(a, b));

    private sealed class FakeDrives(Func<IReadOnlyList<DriveTemperatureSample>> read) : IDriveTemperatureSource
    {
        public IReadOnlyList<DriveTemperatureSample> Read() => read();
    }

    [Fact]
    public void ReadDrives_KeepsPlausibleNamedTemperatures_AndSurvivesAFailure()
    {
        var drives = OwnSensorSources.ReadDrives(new FakeDrives(() =>
            [new("KIOXIA KBG50ZNV512G", 36), new("No temp", null), new("Zero", 0), new("  ", 40)]));
        var only = Assert.Single(drives);
        Assert.Equal(("KIOXIA KBG50ZNV512G", HardwareKind.Storage, 36.0), (only.HardwareName, only.HardwareType, only.Value!.Value));
        Assert.True(only.IsLive);

        Assert.Empty(OwnSensorSources.ReadDrives(new FakeDrives(() => throw new IOException("WMI down"))));
        Assert.Empty(OwnSensorSources.ReadDrives(null));
    }

    private sealed class StorageWmi : RemotePCDiagnostics.Core.DataSources.IWmiSource
    {
        public int DiskQueries { get; private set; }
        public Task<RemotePCDiagnostics.Core.DataSources.WmiQueryResult> QueryAsync(string ns, string wql, CancellationToken ct = default)
        {
            IEnumerable<KeyValuePair<string, object?>>[] rows;
            if (wql == DriveReader.DiskSql)
            {
                DiskQueries++;
                rows = [new Dictionary<string, object?> { ["ObjectId"] = "disk-1", ["DeviceId"] = "0", ["FriendlyName"] = "KIOXIA KBG50ZNV512G" }];
            }
            else if (wql.StartsWith("ASSOCIATORS", StringComparison.Ordinal))
                rows = [new Dictionary<string, object?> { ["Temperature"] = 37 }];
            else rows = [];
            return Task.FromResult(new RemotePCDiagnostics.Core.DataSources.WmiQueryResult(ns, wql,
                [.. rows.Select(RemotePCDiagnostics.Core.DataSources.WmiRow.From)]));
        }
    }

    [Fact]
    public void WmiDriveTemperatureSource_ReadsReliabilityCounters_AndReusesARecentRead()
    {
        var wmi = new StorageWmi();
        var now = new DateTime(2026, 11, 27, 15, 0, 0, DateTimeKind.Utc);
        var source = new WmiDriveTemperatureSource(wmi, reuseFor: TimeSpan.FromSeconds(10), utcNow: () => now);

        Assert.Equal([new DriveTemperatureSample("KIOXIA KBG50ZNV512G", 37)], source.Read());
        now = now.AddSeconds(5);
        source.Read();
        Assert.Equal(1, wmi.DiskQueries);
        now = now.AddSeconds(6);
        source.Read();
        Assert.Equal(2, wmi.DiskQueries);
    }
}
