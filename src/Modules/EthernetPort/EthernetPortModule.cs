using System.Diagnostics;
using static RemotePCDiagnostics.Core.Areas.EthernetPort;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The interactive Ethernet port test (<see cref="EthernetPort"/> has its rules). Waits up to <see cref="EthernetPort.LinkWindow"/> for a
/// cable or a loopback plug, then: with a cable, waits for an address and pings the card's own address and the DHCP server, and reads the
/// agreed speed and duplex; with a loopback plug, sends <see cref="EthernetPort.LoopbackFrames"/> broadcasts out of the card and compares
/// its own sent and received counters. It changes nothing on the PC, so there is nothing to restore when it is cancelled.
/// </summary>
public sealed class EthernetPortModule(INicHardwareSource hardware, IEthernetPortIo io, INicLinkProbe probe, ILogger? log = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null) : OnDemandModuleBase(log), IEthernetPortModule
{
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public override string Name => ModuleSlugs.EthernetPort;
    public override Guid Id => ModuleIds.EthernetPort;
    public override string DisplayName => "Ethernet port test";
    public EthernetPortSettings Settings { get; } = new();

    public async Task<IReadOnlyList<EthernetPortChoice>> ListPortsAsync(CancellationToken ct) =>
        (await hardware.ReadAsync(ct).ConfigureAwait(false))?.Adapters.Where(a => a.Medium == NicMedium.Ethernet)
            .Select(a => new EthernetPortChoice(a.Name, a.Description, a.Connected)).ToList() ?? [];

    public bool DropsSession(string adapter) => io.IsOnlyRoute(adapter);

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var mode = Settings.Mode;
        progress?.Report("Finding the wired network ports…");
        var snapshot = await hardware.ReadAsync(ct).ConfigureAwait(false);
        var ports = snapshot?.Adapters.Where(a => a.Medium == NicMedium.Ethernet).ToList() ?? [];
        var port = ports.FirstOrDefault(a => Settings.Adapter is null || a.Name.Equals(Settings.Adapter, StringComparison.OrdinalIgnoreCase));
        if (port is null) return ToResult(Empty(EthernetPortOutcome.NoPort, mode, Settings.Adapter, null));
        var setting = snapshot!.SpeedSettings?.FirstOrDefault(s => s.Adapter.Equals(port.Name, StringComparison.OrdinalIgnoreCase));
        var gigabit = NicHardware.IsGigabitCapable(port, setting);

        // 1. Wait for the link: the person plugs the cable or the plug in now if it isn't already.
        var started = Stopwatch.GetTimestamp();
        EthernetLink? link = null;
        for (var waited = TimeSpan.Zero; ; waited += Poll)
        {
            link = io.Read(port.Name);
            if (link is { Up: true }) break;
            if (waited >= LinkWindow) break;
            var left = LinkWindow - waited;
            progress?.Report(mode == EthernetPortMode.Loopback
                ? $"Plug the loopback plug into {port.Name}… ({left.TotalSeconds:0} s left)"
                : $"Plug a network cable into {port.Name}… ({left.TotalSeconds:0} s left)");
            await _delay(Poll, ct).ConfigureAwait(false);
        }
        var linkWait = Math.Round(Stopwatch.GetElapsedTime(started).TotalSeconds, 1);
        if (link is not { Up: true })
        {
            Log($"{Name}: no link on '{port.Description}' after {linkWait} s (mode {mode})");
            return ToResult(Empty(EthernetPortOutcome.NoCable, mode, port.Name, port.Description) with { LinkWaitSeconds = linkWait });
        }
        progress?.Report($"Link up on {port.Name} at {NetworkAdapter.FormatSpeed(link.SpeedBps)}. Waiting for an address…");

        // 2. An address: a DHCP lease from the network, or the 169.254 one Windows picks on a plug when no DHCP server answers.
        for (var waited = TimeSpan.Zero; waited < AddressWindow; waited += Poll)
        {
            if (link is { Up: true, Ipv4: not null } && (mode == EthernetPortMode.Loopback || !link.Autoconfig || waited >= AddressWindow / 2)) break;
            await _delay(Poll, ct).ConfigureAwait(false);
            link = io.Read(port.Name) ?? link;
        }
        // Duplex as Windows has it now (MSFT_NetAdapter): it is only known once the link is up.
        var now = (await hardware.ReadAsync(ct).ConfigureAwait(false))?.Adapters.FirstOrDefault(a => a.Name.Equals(port.Name, StringComparison.OrdinalIgnoreCase));
        var speed = Math.Max(now?.ReceiveBps ?? 0, now?.TransmitBps ?? 0) is > 0 and var s ? s : link.SpeedBps;
        var report = Empty(EthernetPortOutcome.Passed, mode, port.Name, port.Description) with
        {
            LinkWaitSeconds = linkWait, SpeedBps = speed > 0 ? speed : null, FullDuplex = now?.FullDuplex, GigabitCapable = gigabit,
        };
        Log($"{Name}: link on '{port.Description}' after {linkWait} s, {speed} bps, duplex={now?.FullDuplex}, ipv4={(link.Ipv4 is null ? "none" : link.Autoconfig ? "autoconfig" : "dhcp/static")}, gateway={link.HasGateway}");

        if (mode == EthernetPortMode.Loopback)
        {
            if (link.HasGateway || link.HasDhcpServer || link.Ipv4 is not null && !link.Autoconfig)
                return ToResult(report with { Outcome = EthernetPortOutcome.NotLoopback });
            if (link.Ipv4 is null || link.Mask is null)
                return ToResult(report with { Outcome = EthernetPortOutcome.Failed, FramesSent = 0, FramesCountedOut = 0, FramesCountedIn = 0 });
            progress?.Report($"Sending {LoopbackFrames} test frames through the loopback plug…");
            var before = io.Read(port.Name) ?? link;
            var sent = io.SendBroadcasts(link.Ipv4, link.Mask, LoopbackFrames);
            await _delay(SettleTime, ct).ConfigureAwait(false);
            var after = io.Read(port.Name) ?? before;
            var outCount = Math.Max(0, after.NonUnicastOut - before.NonUnicastOut);
            var inCount = Math.Max(0, after.NonUnicastIn - before.NonUnicastIn);
            Log($"{Name}: loopback sent={sent} countedOut={outCount} countedIn={inCount}");
            return ToResult(report with { Outcome = JudgeLoopback(sent, outCount, inCount), FramesSent = sent, FramesCountedOut = outCount, FramesCountedIn = inCount });
        }

        progress?.Report($"Pinging this PC's own address and the DHCP server on {port.Name}…");
        var pings = await probe.ProbeAsync(port.Name, ct).ConfigureAwait(false);
        Log($"{Name}: pings {string.Join(", ", pings.Select(p => $"{p.Target} {p.Replies}/{p.Sent}"))}");
        var own = pings.FirstOrDefault(p => p.Target == "Own address");
        var r = report with
        {
            GotDhcpAddress = link.Ipv4 is null || link.Autoconfig ? false : link.HasDhcpServer || link.HasGateway ? true : null,
            Pings = pings.Select(p => new EthernetPing(p.Target, p.Sent, p.Replies)).ToList(),
        };
        var (status, _) = Outcome(r);
        return ToResult(r with
        {
            Outcome = own is null && link.Ipv4 is null ? EthernetPortOutcome.Warning
                : status switch { DiagnosticStatus.Ok => EthernetPortOutcome.Passed, DiagnosticStatus.Error => EthernetPortOutcome.Failed, _ => EthernetPortOutcome.Warning },
        });
    }

    private static EthernetPortReport Empty(EthernetPortOutcome o, EthernetPortMode mode, string? adapter, string? description) =>
        new(o, mode, adapter, description, null, null, null, null, null, [], null, null, null);
}
