using System.Diagnostics;
using System.Runtime.CompilerServices;
using static RemotePCDiagnostics.Core.Areas.WifiConnect;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The interactive Wi-Fi connect test (<see cref="WifiConnect"/> has its rules): disconnects, joins the picked network (a saved profile, or a
/// temporary profile with the typed password), waits for an address, pings the router and the internet for 30 s while sampling the
/// signal, then goes back to the network the PC was on. The original network is noted in <see cref="WifiRestoreMarker"/> first, and
/// restored in a finally block, so cancelling or a dropped remote session can't leave the PC on the test's network.
/// </summary>
public sealed class WifiConnectModule(IWifiRadioSource radio, IWifiConnector wifi, WifiRestoreMarker marker, ILogger? log = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null, Func<string, TimeSpan, CancellationToken, Task<long?>>? ping = null,
    Func<string, bool>? isOnlyRoute = null) : OnDemandModuleBase(log), IWifiConnectModule
{
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;
    private readonly Func<string, TimeSpan, CancellationToken, Task<long?>> _ping = ping ?? PingAsync;
    private readonly Func<string, bool> _isOnlyRoute = isOnlyRoute ?? IsOnlyRoute;
    private readonly SemaphoreSlim _switching = new(1, 1);

    public override string Name => ModuleSlugs.WifiConnect;
    public override Guid Id => ModuleIds.WifiConnect;
    public override string DisplayName => "Wi-Fi connect test";
    public WifiConnectSettings Settings { get; } = new();

    public Task<WifiRadioReading> ScanAsync(CancellationToken ct) => radio.ReadAsync(scan: true, ct);

    /// <summary>Whether starting the test would drop a remote session (the Wi-Fi adapter is the PC's only way out).</summary>
    public bool DropsSession(string interfaceId) => _isOnlyRoute(interfaceId);

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var password = Settings.Password;
        Settings.Password = null;
        progress?.Report("Reading the Wi-Fi adapter…");
        var reading = await radio.ReadAsync(scan: false, ct).ConfigureAwait(false);
        var adapter = reading.Interfaces.FirstOrDefault(i => i.RadioOn && (Settings.InterfaceId is null || string.Equals(i.Id, Settings.InterfaceId, StringComparison.OrdinalIgnoreCase)));
        if (adapter is null) return ToResult(Report(WifiConnectOutcome.NoAdapter, null, null, null));

        var ssid = Settings.Ssid is { Length: > 0 } picked ? picked : adapter.ConnectedSsid;
        if (ssid is null) return ToResult(Report(WifiConnectOutcome.NoNetwork, null, null, adapter.Description));
        var seen = adapter.Networks.FirstOrDefault(n => n.Ssid == ssid);
        var profile = seen?.ProfileName ?? (ssid == adapter.ConnectedSsid ? adapter.ConnectedProfile : null);
        string? xml = null;
        if (profile is null)
        {
            xml = ProfileXml(ssid, seen?.Security ?? "WPA2-Personal", password);
            if (xml is null) return ToResult(Report(WifiConnectOutcome.NeedsPassword, ssid, null, adapter.Description));
        }
        var mode = profile is not null ? "Saved profile" : seen?.Security is WifiRadio.Open or WifiRadio.Owe ? "Open network" : "Typed password";

        await _switching.WaitAsync(ct).ConfigureAwait(false);
        var before = wifi.Read(adapter.Id);
        var original = before is { IsConnected: true } ? before : null;
        marker.Save(new(adapter.Id, original?.Profile, original?.Ssid, DateTimeOffset.Now));
        Log($"{Name}: start adapter='{adapter.Description}' mode={mode} sameNetwork={original?.Ssid == ssid} onlyRoute={_isOnlyRoute(adapter.Id)}");
        var changed = new StrongBox<bool>();
        WifiConnectReport report;
        var restore = WifiRestoreOutcome.NotNeeded;
        try
        {
            report = await TestAsync(adapter, ssid, mode, profile, xml, original, changed, progress, ct).ConfigureAwait(false);
        }
        finally
        {
            // Runs on success, failure and cancel alike; never with the run's token, which may be the one that was cancelled.
            if (changed.Value) restore = await RestoreAsync(adapter.Id, original?.Profile, original?.Ssid, CancellationToken.None).ConfigureAwait(false);
            else marker.Clear();
            _switching.Release();
        }
        return ToResult(report with { Restore = restore, OriginalSsid = original?.Ssid });
    }

    private async Task<WifiConnectReport> TestAsync(WifiRadioInterface adapter, string ssid, string mode, string? profile, string? xml, WifiLinkState? original,
        StrongBox<bool> changed, IProgress<string>? progress, CancellationToken ct)
    {
        if (original is not null)
        {
            changed.Value = true;
            progress?.Report("Disconnecting the Wi-Fi…");
            wifi.Disconnect(adapter.Id);
            await WaitAsync(() => wifi.Read(adapter.Id) is not { IsConnected: true }, DisconnectWindow, ct).ConfigureAwait(false);
        }
        progress?.Report($"Connecting to {ssid}…");
        changed.Value = true;
        var error = profile is not null ? wifi.ConnectProfile(adapter.Id, profile) : wifi.ConnectTemporary(adapter.Id, xml!);
        if (error != 0) return Report(WifiConnectOutcome.ConnectRefused, ssid, mode, adapter.Description) with { ErrorCode = error };

        var connectedAfter = await WaitAsync(() => wifi.Read(adapter.Id) is { IsConnected: true } s && s.Ssid == ssid, ConnectWindow, ct).ConfigureAwait(false);
        if (connectedAfter is null) return Report(WifiConnectOutcome.CouldNotConnect, ssid, mode, adapter.Description);
        Log($"{Name}: connected after {connectedAfter.Value.TotalSeconds:0.0} s");

        progress?.Report($"Connected to {ssid}. Waiting for an address…");
        string? gateway = null;
        if (await WaitAsync(() => (gateway = wifi.Gateway(adapter.Id)) is not null, AddressWindow, ct).ConfigureAwait(false) is null)
            return Report(WifiConnectOutcome.NoAddress, ssid, mode, adapter.Description) with { ConnectSeconds = Secs(connectedAfter) };

        var (gw, net, rssi) = await PingLoopAsync(adapter.Id, gateway!, progress, ct).ConfigureAwait(false);
        var avg = rssi.Count > 0 ? Math.Round(rssi.Average(), 1) : (double?)null;
        Log($"{Name}: router loss {gw.LossPercent}% avg {gw.AverageMs} ms, internet loss {net.LossPercent}%, rssi {(rssi.Count > 0 ? $"{rssi.Min()}..{rssi.Max()}" : "n/a")}");
        return new WifiConnectReport(Judge(gw, net, avg), ssid, mode, adapter.Description, Secs(connectedAfter), gateway, gw, net,
            rssi.Count > 0 ? rssi.Min() : null, rssi.Count > 0 ? rssi.Max() : null, avg, WifiRestoreOutcome.NotNeeded, original?.Ssid);
    }

    private static double? Secs(TimeSpan? t) => t is { } v ? Math.Round(v.TotalSeconds, 1) : null;

    private WifiConnectReport Report(WifiConnectOutcome o, string? ssid, string? mode, string? adapter) =>
        new(o, ssid, mode, adapter, null, null, null, null, null, null, null, WifiRestoreOutcome.NotNeeded, null);

    private async Task<(PingStats Gateway, PingStats Internet, List<int> Rssi)> PingLoopAsync(string adapterId, string gateway, IProgress<string>? progress, CancellationToken ct)
    {
        var gw = new List<long?>();
        var net = new List<long?>();
        var rssi = new List<int>();
        var rounds = (int)(PingTime / PingInterval);
        for (var i = 0; i < rounds; i++)
        {
            progress?.Report($"Pinging the router and the internet… {rounds - i} s left");
            var started = Stopwatch.GetTimestamp();
            var a = _ping(gateway, PingTimeout, ct);
            var b = _ping(InternetHost, PingTimeout, ct);
            gw.Add(await a.ConfigureAwait(false));
            net.Add(await b.ConfigureAwait(false));
            if (wifi.Read(adapterId)?.Rssi is { } r) rssi.Add(r);
            var left = PingInterval - Stopwatch.GetElapsedTime(started);
            if (left > TimeSpan.Zero) await _delay(left, ct).ConfigureAwait(false);
        }
        return (PingStats.From("Router", gw), PingStats.From("Internet", net), rssi);
    }

    /// <summary>Back to <paramref name="profile"/> (or disconnected when the adapter wasn't connected before), then clears the marker.</summary>
    private async Task<WifiRestoreOutcome> RestoreAsync(string adapterId, string? profile, string? ssid, CancellationToken ct)
    {
        try
        {
            if (profile is null)
            {
                wifi.Disconnect(adapterId);
                marker.Clear();
                return WifiRestoreOutcome.Disconnected;
            }
            if (wifi.Read(adapterId) is { IsConnected: true } now && now.Profile == profile)
            {
                marker.Clear();
                return WifiRestoreOutcome.Restored;
            }
            for (var attempt = 1; attempt <= 2; attempt++)
            {
                var error = wifi.ConnectProfile(adapterId, profile);
                Log($"{Name}: restoring the original network, attempt {attempt}, WLAN error {error}");
                if (error == 0 && await WaitAsync(() => wifi.Read(adapterId) is { IsConnected: true } s && s.Profile == profile, RestoreWindow / 2, ct).ConfigureAwait(false) is not null)
                {
                    marker.Clear();
                    return WifiRestoreOutcome.Restored;
                }
            }
            LogWarn($"{Name}: couldn't reconnect to the original network; the marker is kept so the next start tries again");
            return WifiRestoreOutcome.Failed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError($"{Name}: restore failed: {ex.Message}");
            return WifiRestoreOutcome.Failed;
        }
    }

    /// <summary>Restores what an unfinished test left (see <see cref="WifiRestoreMarker"/>). Does nothing when no marker is there.</summary>
    public async Task RestorePendingAsync(CancellationToken ct)
    {
        if (marker.Load() is not { } e) return;
        if (DateTimeOffset.Now - e.SavedAt > WifiRestoreMarker.MaxAge) { marker.Clear(); return; }
        if (!await _switching.WaitAsync(0, ct).ConfigureAwait(false)) return;   // a test is running and restores by itself
        try
        {
            Log($"{Name}: an unfinished test left a restore marker; restoring");
            await RestoreAsync(e.InterfaceId, e.Profile, e.Ssid, ct).ConfigureAwait(false);
        }
        finally { _switching.Release(); }
    }

    /// <summary>Polls until <paramref name="done"/> holds; returns how long that took, or null after <paramref name="window"/>.</summary>
    private async Task<TimeSpan?> WaitAsync(Func<bool> done, TimeSpan window, CancellationToken ct)
    {
        for (var waited = TimeSpan.Zero; waited <= window; waited += Poll)
        {
            if (done()) return waited;
            await _delay(Poll, ct).ConfigureAwait(false);
        }
        return null;
    }
}
