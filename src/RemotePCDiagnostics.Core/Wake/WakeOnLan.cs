using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace RemotePCDiagnostics.Core.Wake;

/// <summary>
/// Wake-on-LAN addresses and the magic packet. A packet is six 0xFF bytes followed by the target MAC sixteen times (102 bytes).
/// Nothing here opens a socket.
/// </summary>
public static class WakeAddresses
{
    public const string GlobalBroadcast = "255.255.255.255";
    public const int DiscardPort = 9;
    public const int EchoPort = 7;

    /// <summary>At most this many targets in one command. A shop wakes one PC, or a few; a larger list is refused.</summary>
    public const int MaxMacs = 16;

    /// <summary>At most this many subnet broadcasts in one command.</summary>
    public const int MaxBroadcasts = 8;

    public static readonly int[] Ports = [DiscardPort, EchoPort];

    /// <summary>A unicast MAC (not all-zero, not broadcast, not multicast). Colon, dash or bare hex.</summary>
    public static bool TryParseMac(string? text, out byte[] mac)
    {
        mac = [];
        if (string.IsNullOrWhiteSpace(text)) return false;
        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12) return false;
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (bytes.All(b => b == 0) || bytes.All(b => b == 0xFF)) return false;
        if ((bytes[0] & 0x01) != 0) return false;
        mac = bytes;
        return true;
    }

    /// <summary><c>AA:BB:CC:DD:EE:FF</c>. Empty when <paramref name="mac"/> is not six bytes, or is all zeros.</summary>
    public static string FormatMac(ReadOnlySpan<byte> mac)
    {
        if (mac.Length != 6) return "";
        var bytes = mac.ToArray();
        if (bytes.All(b => b == 0)) return "";
        return string.Join(':', bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    /// <summary>Six 0xFF bytes, then the MAC sixteen times.</summary>
    public static byte[] MagicPacket(ReadOnlySpan<byte> mac)
    {
        if (mac.Length != 6) throw new ArgumentException("A magic packet needs a 6-byte MAC address.", nameof(mac));
        var packet = new byte[6 + 16 * 6];
        packet.AsSpan(0, 6).Fill(0xFF);
        for (var i = 0; i < 16; i++)
            mac.CopyTo(packet.AsSpan(6 + i * 6, 6));
        return packet;
    }

    /// <summary>Four dotted decimals, each 0–255. Rejects the loose forms <see cref="IPAddress.TryParse"/> accepts.</summary>
    public static bool TryIPv4(string? text, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Trim().Split('.');
        if (parts.Length != 4) return false;
        var bytes = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            if (parts[i].Length == 0 || parts[i].Length > 3) return false;
            if (!byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[i])) return false;
        }
        address = new IPAddress(bytes);
        return true;
    }

    /// <summary>169.254.0.0/16. An automatic private address is not a shop subnet.</summary>
    public static bool IsLinkLocal(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return b.Length == 4 && b[0] == 169 && b[1] == 254;
    }

    /// <summary>Network and broadcast for an IPv4 address and a prefix length. False for a prefix outside 0–32.</summary>
    public static bool TrySubnet(IPAddress address, int prefixLength, out IPAddress network, out IPAddress broadcast)
    {
        network = IPAddress.None;
        broadcast = IPAddress.None;
        if (address.AddressFamily != AddressFamily.InterNetwork || prefixLength is < 0 or > 32) return false;
        var raw = address.GetAddressBytes();
        var ip = ((uint)raw[0] << 24) | ((uint)raw[1] << 16) | ((uint)raw[2] << 8) | raw[3];
        var mask = prefixLength switch
        {
            0 => 0u,
            32 => uint.MaxValue,
            _ => uint.MaxValue << (32 - prefixLength),
        };
        network = FromUInt(ip & mask);
        broadcast = FromUInt((ip & mask) | ~mask);
        return true;
    }

    /// <summary>How many leading one-bits a mask has, or 0 when it is not a prefix mask.</summary>
    public static int PrefixOf(IPAddress? mask)
    {
        if (mask is null || mask.AddressFamily != AddressFamily.InterNetwork) return 0;
        var raw = mask.GetAddressBytes();
        var bits = ((uint)raw[0] << 24) | ((uint)raw[1] << 16) | ((uint)raw[2] << 8) | raw[3];
        var prefix = 0;
        var seenZero = false;
        for (var i = 31; i >= 0; i--)
        {
            var one = (bits & (1u << i)) != 0;
            if (one && seenZero) return 0;
            if (one) prefix++;
            else seenZero = true;
        }
        return prefix;
    }

    private static IPAddress FromUInt(uint value) => new(new[]
    {
        (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value,
    });
}

/// <summary>One IPv4 address this computer can send from. <see cref="Broadcast"/> is that address's subnet broadcast.</summary>
public sealed record WakeEndpoint(string Name, string LocalAddress, string Broadcast, int PrefixLength);

/// <summary>One UDP datagram the plan decided to send.</summary>
public sealed record WakePacket(string Mac, string InterfaceName, string LocalAddress, string Destination, int Port, byte[] Payload);

/// <summary>What happened to one datagram, or a MAC the plan refused.</summary>
public sealed record WakeDelivery(string Mac, string Destination, int Port, string InterfaceName, string LocalAddress, bool Sent, string Error);

/// <summary>The packets a command should send. <see cref="Refused"/> is set when nothing may be sent.</summary>
public sealed record WakePlan(bool Refused, string Detail, IReadOnlyList<WakePacket> Packets, IReadOnlyList<WakeDelivery> Rejected);

/// <summary>The outcome of a send: at least one datagram left this computer, or why none did.</summary>
public sealed record WakeAttempt(bool Ok, string Detail, IReadOnlyList<WakeDelivery> Sent);

/// <summary>Sends one datagram. The real one is UDP; tests record the call.</summary>
public interface IWakeTransport
{
    void Send(string localAddress, string destination, int port, byte[] payload);
}

/// <summary>
/// Which datagrams a peer sends. The command names target MACs and the subnet broadcasts of the sleeping PC.
/// An interface matches when its own subnet broadcast is in that list. On each match the packet goes to that
/// subnet broadcast and to 255.255.255.255, on UDP 9 and UDP 7. Sending does not need administrator rights.
/// </summary>
public static class WakeOnLan
{
    public static WakePlan Plan(IReadOnlyList<string>? macs, IReadOnlyList<string>? broadcasts, IReadOnlyList<WakeEndpoint>? endpoints)
    {
        macs ??= [];
        broadcasts ??= [];
        endpoints ??= [];
        if (macs.Count == 0)
            return new(true, "No MAC address was given. Nothing was sent.", [], []);
        if (macs.Count > WakeAddresses.MaxMacs)
            return new(true, $"A wake can name at most {WakeAddresses.MaxMacs} MAC addresses. Nothing was sent.", [], []);
        if (broadcasts.Count == 0)
            return new(true, "No subnet broadcast was given. Nothing was sent.", [], []);
        if (broadcasts.Count > WakeAddresses.MaxBroadcasts)
            return new(true, $"A wake can name at most {WakeAddresses.MaxBroadcasts} subnets. Nothing was sent.", [], []);

        var targets = new List<(string Text, byte[] Bytes)>();
        var rejected = new List<WakeDelivery>();
        foreach (var raw in macs)
        {
            if (WakeAddresses.TryParseMac(raw, out var bytes))
                targets.Add((WakeAddresses.FormatMac(bytes), bytes));
            else
                rejected.Add(new(raw?.Trim() ?? "", "", 0, "", "", false, "Not a MAC address this computer can wake."));
        }
        if (targets.Count == 0)
            return new(true, "None of the MAC addresses could be read. Nothing was sent.", [], rejected);

        var wanted = new HashSet<IPAddress>();
        foreach (var raw in broadcasts)
            if (WakeAddresses.TryIPv4(raw, out var ip)) wanted.Add(ip);
        if (wanted.Count == 0)
            return new(true, "No subnet broadcast was given. Nothing was sent.", [], rejected);

        var packets = new List<WakePacket>();
        foreach (var nic in endpoints)
        {
            if (nic.PrefixLength is <= 0 or >= 32) continue;
            if (!WakeAddresses.TryIPv4(nic.LocalAddress, out var local)) continue;
            if (!WakeAddresses.TryIPv4(nic.Broadcast, out var broadcast)) continue;
            if (WakeAddresses.IsLinkLocal(local) || IPAddress.IsLoopback(local)) continue;
            if (!wanted.Contains(broadcast)) continue;
            if (local.Equals(broadcast)) continue;

            var destinations = new List<string> { nic.Broadcast.Trim() };
            if (!string.Equals(destinations[0], WakeAddresses.GlobalBroadcast, StringComparison.Ordinal))
                destinations.Add(WakeAddresses.GlobalBroadcast);

            foreach (var (text, bytes) in targets)
            {
                var payload = WakeAddresses.MagicPacket(bytes);
                foreach (var destination in destinations)
                {
                    foreach (var port in WakeAddresses.Ports)
                        packets.Add(new(text, nic.Name, nic.LocalAddress.Trim(), destination, port, payload));
                }
            }
        }

        if (packets.Count == 0)
            return new(true, "No adapter on this computer is on that subnet. Nothing was sent.", [], rejected);
        return new(false, "", packets, rejected);
    }

    /// <summary>Sends <paramref name="plan"/> through <paramref name="transport"/>. A transport error is one row, and the rest still go.</summary>
    public static WakeAttempt Deliver(WakePlan plan, IWakeTransport transport)
    {
        if (plan.Packets.Count == 0)
            return new(false, plan.Detail, plan.Rejected);

        var sent = new List<WakeDelivery>(plan.Rejected);
        var ok = 0;
        var failed = 0;
        foreach (var packet in plan.Packets)
        {
            try
            {
                transport.Send(packet.LocalAddress, packet.Destination, packet.Port, packet.Payload);
                sent.Add(new(packet.Mac, packet.Destination, packet.Port, packet.InterfaceName, packet.LocalAddress, true, ""));
                ok++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed++;
                sent.Add(new(packet.Mac, packet.Destination, packet.Port, packet.InterfaceName, packet.LocalAddress, false, Clip(ex.Message)));
            }
        }

        var macs = plan.Packets.Select(p => p.Mac).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var detail = failed == 0
            ? $"Sent {ok} UDP packet{(ok == 1 ? "" : "s")} for {macs} MAC address{(macs == 1 ? "" : "es")}."
            : $"Sent {ok} of {ok + failed} UDP packets. {failed} failed.";
        if (plan.Rejected.Count > 0)
            detail += $" {plan.Rejected.Count} MAC address{(plan.Rejected.Count == 1 ? " was" : "es were")} skipped.";
        return new(ok > 0, detail, sent);
    }

    public static WakeAttempt Execute(IReadOnlyList<string>? macs, IReadOnlyList<string>? broadcasts, IReadOnlyList<WakeEndpoint>? endpoints, IWakeTransport transport) =>
        Deliver(Plan(macs, broadcasts, endpoints), transport);

    private static string Clip(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "The packet was not sent.";
        var line = text.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return line.Length <= 180 ? line : line[..180];
    }
}

/// <summary>UDP broadcast from one local IPv4 address. Binding to that address picks the adapter. No administrator rights.</summary>
public sealed class UdpWakeTransport : IWakeTransport
{
    public void Send(string localAddress, string destination, int port, byte[] payload)
    {
        if (!WakeAddresses.TryIPv4(localAddress, out var local) || !WakeAddresses.TryIPv4(destination, out var dest))
            throw new InvalidOperationException("The wake packet address is not IPv4.");
        if (payload is not { Length: 102 })
            throw new InvalidOperationException("The wake packet is the wrong size.");
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, 1);
        socket.SendTimeout = 1000;
        socket.Bind(new IPEndPoint(local, 0));
        socket.SendTo(payload, new IPEndPoint(dest, port));
    }
}
