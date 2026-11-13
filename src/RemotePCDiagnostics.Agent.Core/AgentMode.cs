using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Agent.Core;

public enum AgentModeKind
{
    /// <summary>No agent install was found, and there is no fresh link status.</summary>
    LocalOnly,
    /// <summary>The agent executable or Windows service is present, but the relay link is not up.</summary>
    InstalledNotConnected,
    /// <summary>The agent has a live AgentHub stream.</summary>
    Connected,
}

/// <summary>Facts the desktop app can check without reading the enrollment key.</summary>
public sealed record AgentModeSignals(
    bool AgentInstalled,
    bool LinkUp,
    DateTimeOffset? LinkUpdatedUtc,
    string? ShopGroup);

/// <summary>What the top-bar badge shows. Session Local / N Remote Users is a separate badge.</summary>
public sealed record AgentModeSnapshot(AgentModeKind Kind, string? ShopGroup)
{
    public static AgentModeSnapshot LocalOnly { get; } = new(AgentModeKind.LocalOnly, null);

    public string Label => Kind switch
    {
        AgentModeKind.Connected when ShopGroup is { Length: > 0 } group => "Agent connected · " + group,
        AgentModeKind.Connected => "Agent connected",
        AgentModeKind.InstalledNotConnected => "Agent installed, not connected",
        _ => "Local only",
    };

    /// <summary>Existing badge classes only. No new colors.</summary>
    public string CssClass => Kind switch
    {
        AgentModeKind.Connected => "badge badge-remote",
        AgentModeKind.InstalledNotConnected => "badge",
        _ => "badge badge-local",
    };

    public string Tooltip => AgentMode.Tooltip;
}

/// <summary>
/// Collapses agent state to what the person at the PC can actually know.
/// Connected means the status file says the stream is up and its timestamp is still fresh (the service rewrites it
/// on each heartbeat). A running Windows service is not treated as connected: the process can be up while the relay
/// is down. The shop group is shown only when the file carries one. The enrollment key is not parsed for a group.
/// </summary>
public static class AgentMode
{
    /// <summary>Three heartbeats (30s) plus slack. A crashed agent stops updating and drops off the badge.</summary>
    public static readonly TimeSpan LinkFreshness = TimeSpan.FromSeconds(90);

    public const string Tooltip = "Remote: read-only checks. Local: interactive tests.";

    public static bool IsFresh(DateTimeOffset updatedUtc, DateTimeOffset utcNow)
    {
        if (updatedUtc > utcNow.AddSeconds(5)) return false;
        return utcNow - updatedUtc <= LinkFreshness;
    }

    public static AgentModeSnapshot From(AgentModeSignals signals, DateTimeOffset utcNow)
    {
        var group = AgentLayout.NormalizeShopGroup(signals.ShopGroup);
        var fresh = signals.LinkUp && signals.LinkUpdatedUtc is { } at && IsFresh(at, utcNow);
        if (fresh)
            return new AgentModeSnapshot(AgentModeKind.Connected, group);
        if (signals.AgentInstalled)
            return new AgentModeSnapshot(AgentModeKind.InstalledNotConnected, null);
        return AgentModeSnapshot.LocalOnly;
    }
}

/// <summary>
/// <c>agent-status.json</c>, rewritten while the AgentHub stream is open. It has no enrollment key.
/// Users can read it; the desktop badge does not need administrator rights.
/// </summary>
public sealed class AgentLinkStatus
{
    [JsonPropertyName("connected")] public bool Connected { get; set; }
    [JsonPropertyName("updatedUtc")] public string UpdatedUtc { get; set; } = "";
    [JsonPropertyName("group")] public string Group { get; set; } = "";

    [JsonIgnore]
    public DateTimeOffset? Updated =>
        DateTimeOffset.TryParse(UpdatedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at) ? at : null;

    public static AgentLinkStatus? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            return JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentLinkStatus);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this, AgentJsonContext.Default.AgentLinkStatus);
}

/// <summary>Remembered "we have seen the desktop install" flag. Not the enrollment key.</summary>
public sealed class AgentHostWatchState
{
    [JsonPropertyName("hostEverSeen")] public bool HostEverSeen { get; set; }

    public static AgentHostWatchState Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new AgentHostWatchState();
        try
        {
            return JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentHostWatchState) ?? new AgentHostWatchState();
        }
        catch (JsonException)
        {
            return new AgentHostWatchState();
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this, AgentJsonContext.Default.AgentHostWatchState);
}

/// <summary>
/// Reads the badge facts. The agent executable is checked every time the install fact is due; the Windows service
/// is asked only when that executable is missing (a custom directory). The status file is re-read only when its
/// timestamp changes. Callers poll this about every few seconds.
/// </summary>
public sealed class AgentModeReader
{
    public static readonly TimeSpan DefaultInstallCheckInterval = TimeSpan.FromSeconds(30);

    private readonly string _agentExePath;
    private readonly string _statusPath;
    private readonly Func<bool> _serviceInstalled;
    private readonly TimeSpan _installCheckInterval;
    private DateTimeOffset _installCheckedAt = DateTimeOffset.MinValue;
    private bool _installed;
    private bool _haveStatusWrite;
    private DateTime _statusWriteUtc;
    private AgentLinkStatus? _status;

    public AgentModeReader(string agentExePath, string statusPath, Func<bool> serviceInstalled, TimeSpan? installCheckInterval = null)
    {
        _agentExePath = agentExePath;
        _statusPath = statusPath;
        _serviceInstalled = serviceInstalled ?? throw new ArgumentNullException(nameof(serviceInstalled));
        _installCheckInterval = installCheckInterval ?? DefaultInstallCheckInterval;
    }

    public AgentModeSnapshot Read(DateTimeOffset utcNow)
    {
        var due = _installCheckedAt == DateTimeOffset.MinValue
            || utcNow < _installCheckedAt
            || utcNow - _installCheckedAt >= _installCheckInterval;
        if (due)
        {
            _installed = FileExists(_agentExePath) || SafeService();
            _installCheckedAt = utcNow;
        }

        var status = ReadStatus();
        return AgentMode.From(new AgentModeSignals(_installed, status?.Connected == true, status?.Updated, status?.Group), utcNow);
    }

    private bool SafeService()
    {
        try { return _serviceInstalled(); }
        catch { return false; }
    }

    private AgentLinkStatus? ReadStatus()
    {
        try
        {
            if (!File.Exists(_statusPath))
            {
                _haveStatusWrite = false;
                _status = null;
                return null;
            }
            var write = File.GetLastWriteTimeUtc(_statusPath);
            if (_haveStatusWrite && write == _statusWriteUtc)
                return _status;
            _status = AgentLinkStatus.Parse(File.ReadAllText(_statusPath));
            _statusWriteUtc = write;
            _haveStatusWrite = true;
            return _status;
        }
        catch
        {
            return null;
        }
    }

    private static bool FileExists(string path)
    {
        try { return File.Exists(path); }
        catch { return false; }
    }
}

/// <summary>Polls <see cref="AgentModeReader"/> off the UI thread and raises <see cref="Changed"/> only when the badge changes.</summary>
public sealed class AgentModeMonitor : IDisposable
{
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(5);

    private readonly Func<DateTimeOffset, AgentModeSnapshot> _read;
    private readonly CancellationTokenSource _cts = new();
    private AgentModeSnapshot _current;
    private int _disposed;

    public AgentModeMonitor(Func<DateTimeOffset, AgentModeSnapshot> read, TimeSpan? pollInterval = null, bool startLoop = true)
    {
        _read = read ?? throw new ArgumentNullException(nameof(read));
        _current = ReadSafe();
        if (!startLoop) return;
        var interval = pollInterval ?? DefaultPollInterval;
        _ = Task.Run(() => LoopAsync(interval));
    }

    public AgentModeSnapshot Current => Volatile.Read(ref _current);

    public event Action? Changed;

    public void Refresh(DateTimeOffset? utcNow = null) => Publish(ReadSafe(utcNow));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        try { _cts.Cancel(); } catch { }
    }

    private async Task LoopAsync(TimeSpan interval)
    {
        try
        {
            using var timer = new PeriodicTimer(interval);
            while (await timer.WaitForNextTickAsync(_cts.Token).ConfigureAwait(false))
                Publish(ReadSafe());
        }
        catch (OperationCanceledException)
        {
            // Disposed.
        }
    }

    private AgentModeSnapshot ReadSafe(DateTimeOffset? utcNow = null)
    {
        try { return _read(utcNow ?? DateTimeOffset.UtcNow); }
        catch { return Current ?? AgentModeSnapshot.LocalOnly; }
    }

    private void Publish(AgentModeSnapshot next)
    {
        if (next == Current) return;
        Volatile.Write(ref _current, next);
        try { Changed?.Invoke(); } catch { }
    }
}
