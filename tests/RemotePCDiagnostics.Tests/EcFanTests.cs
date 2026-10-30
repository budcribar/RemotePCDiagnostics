using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Tests;

/// <summary>Simulated ACPI EC on ports 0x62/0x66 that records every port access.</summary>
internal sealed class FakeEcPorts : IEcPortIo
{
    public Dictionary<byte, byte> Ram { get; } = new() { [0x06] = 0x1E, [0xFE] = 0x00, [0xAB] = 0x50, [0xAD] = 0x21 };
    public List<(byte Port, byte Value)> Writes { get; } = [];
    public bool StuckBusy { get; set; }
    public bool Disposed { get; private set; }
    private bool _expectAddress;
    private byte? _out;

    public byte ReadPort(byte port)
    {
        if (port == 0x66) return (byte)((StuckBusy ? 0x02 : 0) | (_out is null ? 0 : 0x01));
        if (port == 0x62) { var v = _out ?? 0; _out = null; return v; }
        throw new InvalidOperationException($"unexpected read port {port:X2}");
    }

    public void WritePort(byte port, byte value)
    {
        Writes.Add((port, value));
        if (port == 0x66) { Assert.Equal(0x80, value); _expectAddress = true; return; }
        if (port == 0x62 && _expectAddress) { _expectAddress = false; _out = Ram.GetValueOrDefault(value); return; }
        throw new InvalidOperationException($"unexpected write {value:X2} -> {port:X2}");
    }

    public void Dispose() => Disposed = true;
}

internal sealed class FakeEcLock(bool grant = true) : IEcLock
{
    public bool Grant { get; set; } = grant;
    public bool Throw { get; set; }
    public int Held { get; private set; }
    public int Enters { get; private set; }
    public bool TryEnter(TimeSpan timeout) { if (Throw) throw new UnauthorizedAccessException("denied"); if (!Grant) return false; Held++; Enters++; return true; }
    public void Exit() { Assert.True(Held > 0); Held--; }
}

public class EcFanTests
{
    private sealed class Rig
    {
        public FakeEcPorts Ports { get; } = new();
        public FakeEcLock Lock { get; } = new();
        public DateTimeOffset Now = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);
        public List<string> Logs { get; } = [];
        public int FactoryCalls;
        public EcFanMonitor Build(string? model = "82R4", bool pawn = true, bool factoryThrows = false, TimeSpan? interval = null) =>
            new(() => model, () => (pawn, pawn ? "test" : "not installed"),
                () => { FactoryCalls++; if (factoryThrows) throw new InvalidOperationException("no module"); return Ports; },
                Lock, Logs.Add, () => Now, interval, stepTimeout: TimeSpan.FromMilliseconds(5));
        public void Advance(double s) => Now = Now.AddSeconds(s);
    }

    [Theory]
    [InlineData("82R3")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("20XW")]
    public void OtherModels_NeverTouchPawnIo(string? model)
    {
        var rig = new Rig();
        using var m = rig.Build(model);
        Assert.Empty(m.Read());
        Assert.False(m.IsEnabled);
        Assert.Equal(0, rig.FactoryCalls);
        Assert.Empty(rig.Ports.Writes);
    }

    [Fact]
    public void Model82R4_WithoutPawnIo_IsOffAndLogged()
    {
        var rig = new Rig();
        using var m = rig.Build(pawn: false);
        Assert.Empty(m.Read());
        Assert.Equal(0, rig.FactoryCalls);
        Assert.Contains(rig.Logs, l => l.Contains("model=82R4") && l.Contains("not available"));
    }

    [Fact]
    public void ModuleLoadFailure_IsOffAndLogged()
    {
        var rig = new Rig();
        using var m = rig.Build(factoryThrows: true);
        Assert.Empty(m.Read());
        Assert.False(m.IsEnabled);
        Assert.Contains(rig.Logs, l => l.Contains("could not be loaded"));
    }

    [Fact]
    public void Model82R4_ReadsAllowlistedAddressesOnly_WithReadCommand()
    {
        var rig = new Rig();
        using var m = rig.Build();
        var r = m.Read();
        Assert.True(m.IsEnabled);
        Assert.All(rig.Ports.Writes, w => Assert.True((w.Port == 0x66 && w.Value == 0x80) || (w.Port == 0x62 && AcpiEcReader.AllowedAddresses.Contains(w.Value))));
        Assert.Equal(new byte[] { 0x06, 0xFE, 0xAB, 0xAD }, rig.Ports.Writes.Where(w => w.Port == 0x62).Select(w => w.Value));
        Assert.Equal(0, rig.Lock.Held);
        var fan = Assert.Single(r);
        Assert.Equal(EcFanMonitor.CpuFanName, fan.SensorName);
        Assert.Equal(SensorKind.Fan, fan.SensorType);
        Assert.Equal(3000, fan.Value); // 0x1E = 30 -> x100
        Assert.Equal("CPU fan (from laptop controller)", fan.FriendlyName);
        Assert.Contains(rig.Logs, l => l.Contains("first EC sample") && l.Contains("0x06(FANS)=0x1E") && l.Contains("0xFE(FA2S)=0x00") && l.Contains("FAN1=1"));
    }

    [Theory]
    [InlineData(0x00)] [InlineData(0x05)] [InlineData(0x07)] [InlineData(0x62)] [InlineData(0xFF)] [InlineData(0xFD)]
    public void Reader_RejectsNonAllowlistedAddress_WithoutTouchingPorts(int address)
    {
        var ports = new FakeEcPorts();
        Assert.Throws<ArgumentOutOfRangeException>(() => new AcpiEcReader(ports).TryRead((byte)address));
        Assert.Empty(ports.Writes);
    }

    [Fact]
    public void Reader_HasNoWritePath()
    {
        var methods = typeof(AcpiEcReader).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly);
        Assert.Equal(new[] { "TryRead" }, methods.Select(x => x.Name));
        Assert.DoesNotContain(typeof(IEcFanSource).GetMethods(), x => x.Name.Contains("Write"));
    }

    [Fact]
    public void Reader_TimesOutWhenBusy()
    {
        var ports = new FakeEcPorts { StuckBusy = true };
        Assert.Null(new AcpiEcReader(ports, TimeSpan.FromMilliseconds(5)).TryRead(0x06));
        Assert.Empty(ports.Writes); // never sent the command while the EC input buffer was full
    }

    [Fact]
    public void TwoTimeouts_BackOff30s_ThenResume()
    {
        var rig = new Rig();
        using var m = rig.Build();
        Assert.Single(m.Read());
        rig.Ports.StuckBusy = true;
        rig.Advance(2); var cached = m.Read();
        Assert.Single(cached); // failed sample keeps last good values
        Assert.False(m.IsBackingOff);
        rig.Advance(2); m.Read();
        Assert.True(m.IsBackingOff);
        Assert.Contains(rig.Logs, l => l.Contains("backing off"));
        rig.Ports.StuckBusy = false;
        var writes = rig.Ports.Writes.Count;
        rig.Advance(10); m.Read();
        Assert.Equal(writes, rig.Ports.Writes.Count); // no EC access while backing off
        rig.Advance(21); Assert.Single(m.Read());
        Assert.True(rig.Ports.Writes.Count > writes);
        Assert.Equal(0, rig.Lock.Held);
    }

    [Fact]
    public void MutexBusy_SkipsSample_NoPortAccess_AndBacksOff()
    {
        var rig = new Rig();
        rig.Lock.Grant = false;
        using var m = rig.Build();
        Assert.Empty(m.Read());
        rig.Advance(2); Assert.Empty(m.Read());
        Assert.Empty(rig.Ports.Writes);
        Assert.True(m.IsBackingOff);
        Assert.Contains(rig.Logs, l => l.Contains("mutex busy"));
    }

    [Fact]
    public void MutexThrows_IsHandled()
    {
        var rig = new Rig();
        rig.Lock.Throw = true;
        using var m = rig.Build();
        Assert.Empty(m.Read());
        Assert.Empty(rig.Ports.Writes);
        Assert.Contains(rig.Logs, l => l.Contains("mutex error"));
    }

    [Fact]
    public void PollsAtMostOncePerInterval_MinimumOneSecond()
    {
        var rig = new Rig();
        using var m = rig.Build(interval: TimeSpan.FromMilliseconds(100));
        Assert.Equal(TimeSpan.FromSeconds(1), m.PollInterval);
        m.Read(); var n = rig.Lock.Enters;
        rig.Advance(0.5); m.Read();
        Assert.Equal(n, rig.Lock.Enters);
        rig.Advance(0.6); m.Read();
        Assert.Equal(n + 1, rig.Lock.Enters);
        Assert.Equal(TimeSpan.FromSeconds(2), new Rig().Build().PollInterval);
    }

    [Fact]
    public void ConstantZeroOrFF_StaysHidden()
    {
        var rig = new Rig();
        rig.Ports.Ram[0x06] = 0xFF; rig.Ports.Ram[0xFE] = 0x00;
        using var m = rig.Build();
        for (var i = 0; i < 20; i++) { Assert.Empty(m.Read()); rig.Advance(2); }
    }

    [Fact]
    public void Plausibility_ZeroOnlyAfterNonZero_AndOutOfRangeHidden()
    {
        var p = new EcFanPlausibility();
        Assert.Null(p.Accept(0));
        Assert.Null(p.Accept(0xFF));
        Assert.Null(p.Accept(EcFanPlausibility.MaxPlausibleRaw + 1));
        Assert.Equal(2500, p.Accept(25));
        Assert.Equal(0, p.Accept(0)); // fan stopped: valid once proven
        Assert.True(p.SeenChange);
        Assert.Null(p.Accept(0xFF));
        Assert.Equal(8000, p.Accept(EcFanPlausibility.MaxPlausibleRaw));
    }

    [Fact]
    public void Fan2_AppearsWhenItSpinsUp_ThenZeroIsShown()
    {
        var rig = new Rig();
        using var m = rig.Build();
        Assert.DoesNotContain(m.Read(), r => r.SensorName == EcFanMonitor.Fan2Name);
        rig.Ports.Ram[0xFE] = 0x20; rig.Advance(2);
        var f2 = Assert.Single(m.Read(), r => r.SensorName == EcFanMonitor.Fan2Name);
        Assert.Equal(3200, f2.Value);
        rig.Ports.Ram[0xFE] = 0x00; rig.Advance(2);
        f2 = Assert.Single(m.Read(), r => r.SensorName == EcFanMonitor.Fan2Name);
        Assert.Equal(0, f2.Value);
        Assert.Equal(0, f2.Min); Assert.Equal(3200, f2.Max);
    }

    [Fact]
    public void Readings_LandInExistingFanCard()
    {
        var rig = new Rig();
        using var m = rig.Build();
        var report = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot(m.Read(), true));
        Assert.Single(report.Groups.First(g => g.Id == "fans").Readings);
    }

    [Fact]
    public void RollingSummary_And_StressLogging()
    {
        var rig = new Rig();
        using var m = rig.Build();
        m.Read();
        m.SetStressLogging(true);
        for (var i = 0; i < 16; i++) { rig.Ports.Ram[0x06] = (byte)(0x1E + i % 2); rig.Advance(2); m.Read(); }
        m.SetStressLogging(false);
        Assert.True(rig.Logs.Count(l => l.Contains("Fan diagnostic (stress): 0x06=")) >= 16);
        var summary = Assert.Single(rig.Logs, l => l.StartsWith("Fan diagnostic summary:"));
        Assert.Contains("min=0x1E max=0x1F", summary);
        Assert.Contains("last15=[", summary);
    }

    [Fact]
    public void RawStats_CompressesRuns()
    {
        var s = new EcFanMonitor.RawStats();
        foreach (var b in new byte[] { 1, 1, 1, 2, 3, 3 }) s.Add(b);
        Assert.Equal("01x3,02,03x2", s.Recent());
        Assert.Equal(2, s.Changes);
    }

    [Fact]
    public void Dispose_ClosesModule_AndStopsReads()
    {
        var rig = new Rig();
        var m = rig.Build();
        m.Read();
        m.Dispose(); m.Dispose();
        Assert.True(rig.Ports.Disposed);
        Assert.Empty(m.Read());
    }
}
