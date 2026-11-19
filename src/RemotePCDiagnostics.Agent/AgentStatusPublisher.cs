using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Writes <see cref="AgentLayout.StatusFileName"/> for the desktop badge. The shop group is kept once learned so a
/// reconnect does not wipe it. The enrollment key is never written here.
/// </summary>
internal sealed class AgentStatusPublisher
{
    private readonly object _gate = new();
    private bool _connected;
    private string? _group;
    private string? _latestStable;
    private string? _latestPrerelease;

    public void Publish(bool connected, string? group)
    {
        lock (_gate)
        {
            _connected = connected;
            var normalized = AgentLayout.NormalizeShopGroup(group);
            if (normalized is not null)
                _group = normalized;
            if (_group is null)
            {
                var existing = AgentLinkStatus.Parse(ReadQuiet(AgentPaths.StatusPath()));
                _group = AgentLayout.NormalizeShopGroup(existing?.Group);
            }

            WriteLocked();
        }
    }

    public void PublishRelease(string? stableVersion, string? prereleaseVersion)
    {
        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(stableVersion))
                _latestStable = stableVersion.Trim();
            if (!string.IsNullOrWhiteSpace(prereleaseVersion))
                _latestPrerelease = prereleaseVersion.Trim();
            WriteLocked();
        }
    }

    private void WriteLocked()
    {
        var status = new AgentLinkStatus
        {
            Connected = _connected,
            UpdatedUtc = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            Group = _group ?? "",
            LatestStableVersion = _latestStable ?? "",
            LatestPrereleaseVersion = _latestPrerelease ?? "",
        };
        try { AgentPaths.WriteReadableStatus(status); }
        catch { /* A badge that stays stale is safer than crashing the service. */ }
    }

    private static string? ReadQuiet(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch { return null; }
    }
}
