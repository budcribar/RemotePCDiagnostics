using Relay = PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Wake;

namespace RemotePCDiagnostics.Agent;

/// <summary>Maps a wake snapshot onto the relay messages, and sends a magic packet when the relay asks.</summary>
public static class WakeRelay
{
    public static Relay.WakeReadiness ToReadiness(WakeSnapshot snapshot)
    {
        var msg = new Relay.WakeReadiness
        {
            PowerRead = snapshot.PowerRead,
            ModernStandby = snapshot.ModernStandby,
            S3 = snapshot.S3,
            Hibernate = snapshot.Hibernate,
            StandbyNetwork = snapshot.StandbyNetwork ?? "",
        };
        foreach (var adapter in snapshot.Adapters)
        {
            msg.Adapters.Add(new Relay.WakeAdapter
            {
                Name = Clip(adapter.Name, 64),
                Description = Clip(adapter.Description, 128),
                AdapterType = adapter.AdapterType ?? "",
                Mac = Clip(adapter.Mac, 17),
                Ipv4 = Clip(adapter.Ipv4, 15),
                PrefixLength = adapter.PrefixLength,
                Subnet = Clip(adapter.Subnet, 15),
                Broadcast = Clip(adapter.Broadcast, 15),
                WakeArmed = adapter.WakeArmed ?? "",
                MagicPacket = adapter.MagicPacket ?? "",
            });
        }
        return msg;
    }

    public static Relay.WakePacketReport Send(Relay.SendWakeCommand command, IReadOnlyList<WakeEndpoint>? endpoints = null, IWakeTransport? transport = null)
    {
        var attempt = WakeOnLan.Execute(
            command.TargetMac,
            command.Broadcast,
            endpoints ?? WakeInventory.ReadSendEndpoints(),
            transport ?? new UdpWakeTransport());
        var report = new Relay.WakePacketReport
        {
            RequestId = command.RequestId ?? "",
            Ok = attempt.Ok,
            Detail = attempt.Detail ?? "",
        };
        foreach (var row in attempt.Sent)
        {
            report.Sent.Add(new Relay.SentWakePacket
            {
                Mac = row.Mac ?? "",
                Destination = row.Destination ?? "",
                Port = row.Port,
                InterfaceName = row.InterfaceName ?? "",
                InterfaceAddress = row.LocalAddress ?? "",
                Sent = row.Sent,
                Error = row.Error ?? "",
            });
        }
        return report;
    }

    private static string Clip(string? text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[..max];
    }
}

/// <summary>Reads the wake snapshot at most once a minute. powercfg is the slow part; a heartbeat must not run it every time.</summary>
internal sealed class CachingWakeInventory : IDisposable
{
    private readonly TimeSpan _ttl;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SystemCommandRunner _commands = new();
    private WakeSnapshot? _cached;
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    public CachingWakeInventory(TimeSpan? ttl = null) => _ttl = ttl ?? TimeSpan.FromMinutes(2);

    public async Task<WakeSnapshot?> ReadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow - _cachedAt < _ttl)
                return _cached;
            try
            {
                _cached = await WakeInventory.ReadAsync(_commands, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                _cached = null;
            }
            _cachedAt = DateTimeOffset.UtcNow;
            return _cached;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}
