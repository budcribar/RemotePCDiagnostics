using System.Net;
using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Workflow;
using static RemotePCDiagnostics.Tests.Network.NicHardwareTests;

namespace RemotePCDiagnostics.Tests.Network;

/// <summary>The interactive Ethernet port test (#291): wait for a cable or a loopback plug, then pings or loopback frames.</summary>
public sealed class EthernetPortTests
{
    static EthernetPortTests()
    {
        EthernetPort.Poll = TimeSpan.FromSeconds(1);
    }

    private static readonly IPAddress Lan = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Auto = IPAddress.Parse("169.254.10.20");
    private static readonly IPAddress Mask = IPAddress.Parse("255.255.0.0");

    private sealed class FakeIo(Func<int, EthernetLink?> read, Func<int, int>? loopedBack = null) : IEthernetPortIo
    {
        private int _reads;
        private long _in, _out;
        public int Sent { get; private set; }
        public EthernetLink? Read(string adapter)
        {
            var l = read(_reads++);
            return l is null ? null : l with { NonUnicastIn = l.NonUnicastIn + _in, NonUnicastOut = l.NonUnicastOut + _out };
        }
        public int SendBroadcasts(IPAddress from, IPAddress mask, int count)
        {
            Sent += count;
            _out += count;
            _in += loopedBack?.Invoke(count) ?? 0;
            return count;
        }
        public bool IsOnlyRoute(string adapter) => false;
    }

    private static EthernetLink Up(IPAddress? ip, bool auto = false, bool gateway = false, bool dhcp = false) =>
        new(true, 1_000_000_000, ip, Mask, auto, gateway, dhcp, 500, 300);
    private static readonly EthernetLink Down = new(false, 0, null, null, false, false, false, 0, 0);

    private static EthernetPortModule Module(IEthernetPortIo io, EthernetPortMode mode, NicHardwareTests.FakeWmi? wmi = null, INicLinkProbe? probe = null)
    {
        var m = new EthernetPortModule(new WmiNicHardwareSource(wmi ?? NicHardwareTests.Wmi()), io, probe ?? new StubProbe(), delay: (_, _) => Task.CompletedTask);
        m.Settings.Mode = mode;
        return m;
    }

    private static async Task<(DiagnosticResult Result, EthernetPortReport Report)> RunAsync(EthernetPortModule m)
    {
        var r = await m.RefreshAsync(null, TestContext.Current.CancellationToken);
        return (r, Assert.IsType<EthernetPortReport>(r.Payload));
    }

    [Fact]
    public async Task WaitsForTheCableThenPingsAndPasses()
    {
        var io = new FakeIo(i => i < 3 ? Down : Up(Lan, gateway: true, dhcp: true));
        var progress = new List<string>();
        var m = Module(io, EthernetPortMode.Network);
        var r = await m.RefreshAsync(new SyncProgress(progress.Add), TestContext.Current.CancellationToken);
        var rep = Assert.IsType<EthernetPortReport>(r.Payload);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(EthernetPortOutcome.Passed, rep.Outcome);
        Assert.Equal(true, rep.GotDhcpAddress);
        Assert.Equal(2, rep.Pings.Count);
        Assert.Contains(progress, p => p.StartsWith("Plug a network cable into Ethernet", StringComparison.Ordinal));
        Assert.StartsWith("Ethernet passed: 1 Gbps full duplex", r.Message);
    }

    [Fact]
    public async Task NothingPluggedInIsNotAVerdict()
    {
        EthernetPort.LinkWindow = TimeSpan.FromSeconds(3);
        try
        {
            var (r, rep) = await RunAsync(Module(new FakeIo(_ => Down), EthernetPortMode.Network));
            Assert.Equal(EthernetPortOutcome.NoCable, rep.Outcome);
            Assert.Equal(RunEnd.CouldNotRun, rep.RunEnd);
            Assert.Equal(DiagnosticStatus.Warning, r.Status);
        }
        finally { EthernetPort.LinkWindow = TimeSpan.FromMinutes(2); }
    }

    [Fact]
    public async Task NoReplyFromItsOwnAddressFails()
    {
        var (r, rep) = await RunAsync(Module(new FakeIo(_ => Up(Lan, gateway: true, dhcp: true)), EthernetPortMode.Network,
            probe: new StubProbe(new NicPing("Own address", "192.168.1.20", 4, 0), new NicPing("DHCP server", "192.168.1.1", 4, 4))));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(EthernetPortOutcome.Failed, rep.Outcome);
    }

    [Fact]
    public async Task NoDhcpAddressWarns()
    {
        var (r, rep) = await RunAsync(Module(new FakeIo(_ => Up(Auto, auto: true)), EthernetPortMode.Network,
            probe: new StubProbe(new NicPing("Own address", "169.254.10.20", 4, 4))));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(false, rep.GotDhcpAddress);
        Assert.Contains("no DHCP reply", r.Message);
    }

    [Fact]
    public async Task HalfDuplexAndSlowLinksWarn()
    {
        var (half, _) = await RunAsync(Module(new FakeIo(_ => Up(Lan, gateway: true, dhcp: true)), EthernetPortMode.Network, NicHardwareTests.Wmi(adapters: [Nic(duplex: 1)])));
        Assert.Equal(DiagnosticStatus.Warning, half.Status);
        Assert.Contains("half duplex", half.Message);
        var (slow, rep) = await RunAsync(Module(new FakeIo(_ => Up(Lan, gateway: true, dhcp: true)), EthernetPortMode.Network, NicHardwareTests.Wmi(adapters: [Nic(speed: 100_000_000)])));
        Assert.Equal(DiagnosticStatus.Warning, slow.Status);
        Assert.Equal(100_000_000, rep.SpeedBps);
        Assert.Contains("below gigabit", slow.Message);
    }

    [Fact]
    public async Task LoopbackPassesWhenTheFramesComeBack()
    {
        var io = new FakeIo(_ => Up(Auto, auto: true), loopedBack: n => n + 3);   // plus Windows' own broadcasts
        var (r, rep) = await RunAsync(Module(io, EthernetPortMode.Loopback));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(EthernetPort.LoopbackFrames, rep.FramesSent);
        Assert.Equal(EthernetPort.LoopbackFrames, rep.FramesCountedOut);
        Assert.Equal(EthernetPort.LoopbackFrames + 3, rep.FramesCountedIn);
    }

    [Theory]
    [InlineData(0, DiagnosticStatus.Error)]
    [InlineData(50, DiagnosticStatus.Warning)]
    public async Task LoopbackFailsOrWarnsWhenFramesAreLost(int back, DiagnosticStatus expected)
    {
        var (r, _) = await RunAsync(Module(new FakeIo(_ => Up(Auto, auto: true), loopedBack: _ => back), EthernetPortMode.Loopback));
        Assert.Equal(expected, r.Status);
        if (back == 0) Assert.Contains("didn't come back", r.Message);
    }

    [Fact]
    public async Task LoopbackOnARealNetworkIsNotAVerdict()
    {
        var io = new FakeIo(_ => Up(Lan, gateway: true, dhcp: true), loopedBack: n => n);
        var (r, rep) = await RunAsync(Module(io, EthernetPortMode.Loopback));
        Assert.Equal(EthernetPortOutcome.NotLoopback, rep.Outcome);
        Assert.Equal(0, io.Sent);
        Assert.Contains("not a loopback plug", r.Message);
    }

    [Fact]
    public async Task NoWiredPortIsNotAVerdict()
    {
        var (_, rep) = await RunAsync(Module(new FakeIo(_ => Down), EthernetPortMode.Network, NicHardwareTests.Wmi(adapters: [Nic(name: "Wi-Fi", medium: 9)])));
        Assert.Equal(EthernetPortOutcome.NoPort, rep.Outcome);
    }

    [Theory]
    [InlineData(100, 100, 100, EthernetPortOutcome.Passed)]
    [InlineData(100, 100, 90, EthernetPortOutcome.Passed)]
    [InlineData(100, 100, 89, EthernetPortOutcome.Warning)]
    [InlineData(100, 100, 9, EthernetPortOutcome.Failed)]
    [InlineData(100, 10, 100, EthernetPortOutcome.Failed)]
    [InlineData(0, 0, 0, EthernetPortOutcome.Failed)]
    public void JudgesTheLoopbackCounters(int sent, long countedOut, long countedIn, EthernetPortOutcome expected) =>
        Assert.Equal(expected, EthernetPort.JudgeLoopback(sent, countedOut, countedIn));

    [Fact]
    public void TheInteractivePageExportsTheEthernetTest()
    {
        var rep = new EthernetPortReport(EthernetPortOutcome.Passed, EthernetPortMode.Loopback, "Ethernet", "I219", 4, 100_000_000, true, true, null, [], 100, 100, 101);
        var page = new InteractiveExport.PageState("ethernet", ["ethernet"], false, false, false, false);
        var json = InteractiveExport.ToJson(page, new PhysicalBenchQaService().Current,
            new(DiagnosticResult.NotRun(ModuleSlugs.Webcam), false), new(DiagnosticResult.NotRun(ModuleSlugs.SpeakerToMic), false),
            new(DiagnosticResult.NotRun(ModuleSlugs.MicToSpeaker), false), ethernet: EthernetPort.ToResult(rep),
            ethernetPane: new([new("Ethernet", "I219", true)], "Ethernet", EthernetPortMode.Loopback, true));
        using var doc = JsonDocument.Parse(json);
        var t = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "ethernet");
        Assert.True(t.GetProperty("open").GetBoolean());
        Assert.Equal("passed", t.GetProperty("result").GetString());
        Assert.Equal("loopback", t.GetProperty("mode").GetString());
        Assert.True(t.GetProperty("dropsRemoteSession").GetBoolean());
        Assert.Equal(101, t.GetProperty("measured").GetProperty("framesCountedIn").GetInt64());
        Assert.Equal(100, t.GetProperty("measured").GetProperty("speedMbps").GetInt64());
    }

    private sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }
}
