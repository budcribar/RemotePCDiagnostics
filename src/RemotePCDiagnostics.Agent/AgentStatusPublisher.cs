using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Writes <see cref="AgentLayout.StatusFileName"/> for the desktop badge. The shop group is kept once learned so a
/// reconnect does not wipe it. The enrollment key is never written here.
/// </summary>
internal sealed class AgentStatusPublisher
{
    private readonly object _gate = new();
    private string? _group;

    public void Publish(bool connected, string? group)
    {
        lock (_gate)
        {
            var normalized = AgentLayout.NormalizeShopGroup(group);
            if (normalized is not null)
                _group = normalized;
            if (_group is null)
            {
                var existing = AgentLinkStatus.Parse(ReadQuiet(AgentPaths.StatusPath()));
                _group = AgentLayout.NormalizeShopGroup(existing?.Group);
            }

            var status = new AgentLinkStatus
            {
                Connected = connected,
                UpdatedUtc = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                Group = _group ?? "",
            };
            try { AgentPaths.WriteReadableStatus(status); }
            catch { /* A badge that stays stale is safer than crashing the service. */ }
        }
    }

    private static string? ReadQuiet(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch { return null; }
    }
}
