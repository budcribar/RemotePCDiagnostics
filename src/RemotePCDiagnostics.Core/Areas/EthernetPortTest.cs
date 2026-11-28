using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RemotePCDiagnostics.Core.Areas;

// The interactive Ethernet port test (DiagnosticTest #291): waits for a cable or a loopback plug in one wired port, then proves the port
// works. With a cable to the network it pings the card's own address and the DHCP server and reads the agreed speed and duplex. With a
// loopback plug (send pins wired to receive pins) it sends test frames and checks the card's own receive counter saw them come back.
// It all runs in the app without administrator rights: the frames are ordinary UDP broadcasts out of that card, and the counters are the
// card's interface statistics. It changes nothing on the PC.

/// <summary>What is plugged into the port under test.</summary>
public enum EthernetPortMode { Network, Loopback }

public enum EthernetPortOutcome
{
    Passed, Warning, Failed,
    /// <summary>No wired network card on this PC (or the picked one is gone).</summary>
    NoPort,
    /// <summary>Nothing was plugged in before the wait ran out.</summary>
    NoCable,
    /// <summary>Loopback mode, but the port is on a network (it has a DHCP address or a router).</summary>
    NotLoopback,
}

/// <summary>The page's picks for the next run (set by the Interactive tests page just before it starts the test).</summary>
public sealed class EthernetPortSettings
{
    /// <summary>The adapter's connection name ("Ethernet"); null = the first wired card.</summary>
    public string? Adapter { get; set; }
    public EthernetPortMode Mode { get; set; }
}

/// <summary>A wired port's state now, as Windows' interface table has it.</summary>
/// <param name="Ipv4">The card's IPv4 address and its mask; null while it has none.</param>
/// <param name="Autoconfig">The IPv4 address is a 169.254.x.x one Windows picked because no DHCP server answered.</param>
/// <param name="NonUnicastIn">Broadcast and multicast frames the card received since it started (its own counter).</param>
public sealed record EthernetLink(bool Up, long SpeedBps, IPAddress? Ipv4, IPAddress? Mask, bool Autoconfig, bool HasGateway, bool HasDhcpServer,
    long NonUnicastIn, long NonUnicastOut);

/// <summary>What the test asks of the PC (Windows' interface table and a UDP socket); a fake stands in for tests.</summary>
public interface IEthernetPortIo
{
    EthernetLink? Read(string adapter);
    /// <summary>Sends <paramref name="count"/> small UDP broadcasts out of the card that owns <paramref name="from"/>; returns how many were sent.</summary>
    int SendBroadcasts(IPAddress from, IPAddress mask, int count);
    /// <summary>Whether this adapter carries the PC's only route out (unplugging it drops a remote session).</summary>
    bool IsOnlyRoute(string adapter);
}

/// <summary>A ping series in the report.</summary>
public sealed record EthernetPing(string Target, int Sent, int Replies);

/// <param name="LinkWaitSeconds">How long the test waited for a cable or plug (0 when one was already in).</param>
/// <param name="FramesSent">Loopback: broadcasts sent, then how many the card counted going out and coming back in.</param>
public sealed record EthernetPortReport(EthernetPortOutcome Outcome, EthernetPortMode Mode, string? Adapter, string? Description, double? LinkWaitSeconds,
    long? SpeedBps, bool? FullDuplex, bool? GigabitCapable, bool? GotDhcpAddress, IReadOnlyList<EthernetPing> Pings,
    int? FramesSent, long? FramesCountedOut, long? FramesCountedIn) : IRunEnd
{
    /// <summary>No port, nothing plugged in, or no loopback plug: not a verdict on the card.</summary>
    public RunEnd RunEnd => Outcome is EthernetPortOutcome.NoPort or EthernetPortOutcome.NoCable or EthernetPortOutcome.NotLoopback ? RunEnd.CouldNotRun : RunEnd.Finished;
}

public static class EthernetPort
{
    /// <summary>How long the test waits for a cable or plug to be plugged in.</summary>
    public static readonly TimeSpan LinkWindow = TimeSpan.FromMinutes(2);
    /// <summary>How long it waits for an address after the link comes up (a DHCP lease, or Windows' own 169.254 one on a plug).</summary>
    public static readonly TimeSpan AddressWindow = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Poll = TimeSpan.FromSeconds(1);
    /// <summary>How long to let the frames come back before reading the counters again.</summary>
    public static readonly TimeSpan SettleTime = TimeSpan.FromSeconds(2);
    public const int LoopbackFrames = 100;

    /// <summary>The loopback verdict from the counters: went out, came back, or lost on the way.</summary>
    public static EthernetPortOutcome JudgeLoopback(int sent, long countedOut, long countedIn)
    {
        if (sent == 0 || countedOut < sent / 2) return EthernetPortOutcome.Failed;
        if (countedIn >= sent * 9 / 10) return EthernetPortOutcome.Passed;
        return countedIn < sent / 10 ? EthernetPortOutcome.Failed : EthernetPortOutcome.Warning;
    }

    public static (DiagnosticStatus Status, string Message) Outcome(EthernetPortReport r)
    {
        var port = r.Adapter ?? "the port";
        var speed = r.SpeedBps is { } s ? NetworkAdapter.FormatSpeed(s) : null;
        switch (r.Outcome)
        {
            case EthernetPortOutcome.NoPort: return (DiagnosticStatus.Warning, "No wired network port found on this PC.");
            case EthernetPortOutcome.NoCable:
                return (DiagnosticStatus.Warning, r.Mode == EthernetPortMode.Loopback
                    ? $"Nothing was plugged into {port} in {LinkWindow.TotalMinutes:0} minutes. Plug the loopback plug in and run the test again. If it is in, the port or plug isn't making a link."
                    : $"No cable was plugged into {port} in {LinkWindow.TotalMinutes:0} minutes. Plug a network cable in and run the test again. If it is in, try another cable and switch port.");
            case EthernetPortOutcome.NotLoopback:
                return (DiagnosticStatus.Warning, $"{port} is connected to a network, not a loopback plug. Choose Cable to network, or plug the loopback plug in instead.");
        }
        if (r.Mode == EthernetPortMode.Loopback)
        {
            var counts = $"{r.FramesSent} test frames sent, {r.FramesCountedOut} counted going out, {r.FramesCountedIn} back in";
            return r.Outcome switch
            {
                EthernetPortOutcome.Passed => (DiagnosticStatus.Ok, $"Loopback passed on {port}{(speed is null ? "" : $" at {speed}")}: {counts}."),
                EthernetPortOutcome.Warning => (DiagnosticStatus.Warning, $"Some test frames were lost on {port}: {counts}. Reseat the plug and run it again; if frames are still lost, the port is faulty."),
                _ when r.FramesSent is null or 0 || r.FramesCountedOut < r.FramesSent / 2 => (DiagnosticStatus.Error, $"{port} didn't send the test frames ({counts}). The card or its driver is faulty."),
                _ => (DiagnosticStatus.Error, $"The test frames went out of {port} but didn't come back ({counts}). The port's receive side or the plug is faulty: try another plug to be sure."),
            };
        }
        var own = r.Pings.FirstOrDefault(p => p.Target == "Own address");
        var far = r.Pings.FirstOrDefault(p => p.Target != "Own address");
        var parts = new List<string>();
        if (speed is not null) parts.Add($"{speed}{(r.FullDuplex == false ? " half duplex" : r.FullDuplex == true ? " full duplex" : "")}");
        if (own is not null) parts.Add($"own address {own.Replies} of {own.Sent} replies");
        if (far is not null) parts.Add($"{far.Target.ToLowerInvariant()} {far.Replies} of {far.Sent}");
        var detail = string.Join(", ", parts);
        if (own is { Replies: 0 }) return (DiagnosticStatus.Error, $"{port} has a link but the PC didn't answer a ping to its own address ({detail}). Reset the adapter or reinstall its driver.");
        if (r.GotDhcpAddress == false) return (DiagnosticStatus.Warning, $"{port} has a link but got no address from the network (no DHCP reply): check the cable, the switch port and the router ({detail}).");
        if (far is { Replies: 0 }) return (DiagnosticStatus.Warning, $"{port} works on this PC, but the {far.Target.ToLowerInvariant()} didn't answer ping ({detail}). Some routers don't answer ping.");
        if (r.FullDuplex == false) return (DiagnosticStatus.Warning, $"{port} works, but at half duplex ({detail}). Usually a speed forced on one end only, or a hub.");
        if (r.GigabitCapable == true && r.SpeedBps is < 1_000_000_000) return (DiagnosticStatus.Warning, $"{port} works, but below gigabit on a gigabit card ({detail}). Try another cable and switch port.");
        if (far is not null && far.Replies < far.Sent) return (DiagnosticStatus.Warning, $"{port} works, but some pings were lost ({detail}).");
        return (DiagnosticStatus.Ok, $"{port} passed: {detail}.");
    }

    public static DiagnosticResult ToResult(EthernetPortReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<EthernetPortReport>(ModuleSlugs.EthernetPort, status, msg, DateTimeOffset.Now, r);
    }
}

/// <summary><see cref="IEthernetPortIo"/> on Windows' interface table (System.Net.NetworkInformation) and a UDP socket.</summary>
public sealed class SystemEthernetPortIo : IEthernetPortIo
{
    /// <summary>The discard port: anything listening there throws the frames away.</summary>
    public const int DiscardPort = 9;

    private static NetworkInterface? Find(string adapter)
    {
        try { return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name.Equals(adapter, StringComparison.OrdinalIgnoreCase)); }
        catch (NetworkInformationException) { return null; }
    }

    public EthernetLink? Read(string adapter)
    {
        if (Find(adapter) is not { } nic) return null;
        try
        {
            var p = nic.GetIPProperties();
            var v4 = p.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
            var stats = nic.GetIPStatistics();
            var auto = v4 is not null && v4.Address.GetAddressBytes() is [169, 254, ..];
            var nonUnicastOut = 0L;
            if (OperatingSystem.IsWindows())
            {
                try { nonUnicastOut = stats.NonUnicastPacketsSent; }
                catch (PlatformNotSupportedException) { }
            }
            return new EthernetLink(nic.OperationalStatus == OperationalStatus.Up, nic.Speed, v4?.Address, v4?.IPv4Mask, auto,
                p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)),
                OperatingSystem.IsWindows() && p.DhcpServerAddresses.Any(d => d.AddressFamily == AddressFamily.InterNetwork),
                stats.NonUnicastPacketsReceived, nonUnicastOut);
        }
        catch (NetworkInformationException) { return null; }
    }

    public int SendBroadcasts(IPAddress from, IPAddress mask, int count)
    {
        // The subnet's own broadcast address (169.254.255.255 on a plug), so the frames leave by the card that owns `from` and no other.
        var a = from.GetAddressBytes();
        var m = mask.GetAddressBytes();
        var broadcast = new IPAddress(a.Select((b, i) => (byte)(b | ~m[i])).ToArray());
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = true };
        try { socket.Bind(new IPEndPoint(from, 0)); }
        catch (SocketException) { return 0; }
        var payload = "RPCD loopback test frame"u8.ToArray();
        var sent = 0;
        for (var i = 0; i < count; i++)
        {
            try { socket.SendTo(payload, new IPEndPoint(broadcast, DiscardPort)); sent++; }
            catch (SocketException) { }
        }
        return sent;
    }

    public bool IsOnlyRoute(string adapter)
    {
        try
        {
            var withRoute = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .Where(n => n.GetIPProperties().GatewayAddresses.Any(g => !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any)))
                .Select(n => n.Name).ToList();
            return withRoute.Count == 1 && withRoute[0].Equals(adapter, StringComparison.OrdinalIgnoreCase);
        }
        catch (NetworkInformationException) { return false; }
    }
}

/// <summary>A wired port the page lists: its connection name, the card, and whether something is plugged in now.</summary>
public sealed record EthernetPortChoice(string Name, string Description, bool? Connected);

/// <summary>What the Interactive tests page needs from the Ethernet port test module (it lives in its own assembly).</summary>
public interface IEthernetPortModule
{
    EthernetPortSettings Settings { get; }
    /// <summary>The PC's wired network cards (physical Ethernet adapters).</summary>
    Task<IReadOnlyList<EthernetPortChoice>> ListPortsAsync(CancellationToken ct);
    /// <summary>Whether unplugging this port drops a remote session (it carries the PC's only route out).</summary>
    bool DropsSession(string adapter);
}
