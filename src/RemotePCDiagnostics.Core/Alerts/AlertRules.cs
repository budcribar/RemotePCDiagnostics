namespace RemotePCDiagnostics.Core.Alerts;

/// <summary>A Windows event the Agent's watchers passed on: only Critical, Error and Warning events with the IDs in <see cref="AlertRules"/>.</summary>
public sealed record AlertEvent(string Channel, string Provider, int EventId, long RecordId, DateTimeOffset TimeUtc,
    IReadOnlyList<string> Properties, string? Message);

/// <summary>The PC's power as the Agent last read it (every 15 minutes).</summary>
public sealed record PowerReading(DateTimeOffset TimeUtc, bool OnBattery, int? Percent, bool Charging, bool HasBattery);

public sealed record DiskReading(string Drive, double FreeGb, double TotalGb);

/// <summary>What a reading means for its level alert.</summary>
public enum LevelDecision { None, Raise, Clear }

/// <summary>
/// Which Windows events raise which alert (plan v2, section 1), and the thresholds for the 15-minute level reading. Pure, so it is
/// tested without Windows. Text from events is the PC's: it goes into the alert as data.
/// </summary>
public static class AlertRules
{
    public const string SystemChannel = "System";
    public const string ApplicationChannel = "Application";

    /// <summary>The event IDs each channel's watcher asks Windows for (the provider is checked here, since IDs repeat across providers).</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<int>> EventIds = new Dictionary<string, IReadOnlyList<int>>
    {
        [SystemChannel] = [2004, 2013, 7, 51, 153, 52, 55, 98, 41, 86, 1001, 20],
        [ApplicationChannel] = [1000, 1002],
    };

    /// <summary>The XPath query for a channel: those IDs, Critical, Error or Warning only, and newer than <paramref name="afterRecordId"/>.</summary>
    public static string Query(string channel, long afterRecordId = 0, TimeSpan? lookBack = null)
    {
        var ids = string.Join(" or ", EventIds[channel].Select(id => $"EventID={id}"));
        var extra = afterRecordId > 0 ? $" and EventRecordID>{afterRecordId}" : "";
        if (lookBack is { } back) extra += $" and TimeCreated[timediff(@SystemTime) <= {(long)back.TotalMilliseconds}]";
        return $"*[System[({ids}) and (Level=1 or Level=2 or Level=3){extra}]]";
    }

    /// <summary>
    /// The oldest power reading that still says what the PC was doing before an unexpected shutdown. Windows logs event 41 at the next
    /// start, so the reading is the last one saved before the PC went off (readings are every 15 minutes), however long it stayed off.
    /// </summary>
    public static readonly TimeSpan PowerReadingMaxAge = TimeSpan.FromDays(7);

    /// <summary>
    /// The alerts one event raises (none, one, or two for a shutdown on battery). <paramref name="readLevelsNow"/> is set for the
    /// low-disk event, whose drive is read at once instead (the reading names the drive and clears the alert later).
    /// </summary>
    public static IReadOnlyList<AlertSignal> FromEvent(AlertEvent e, AlertSettings settings, PowerReading? lastPower, out bool readLevelsNow)
    {
        readLevelsNow = false;
        var provider = ShortProvider(e.Provider);
        var source = new AlertEventRef(e.Channel, e.Provider, e.EventId, e.RecordId);
        string Prop(int i) => i < e.Properties.Count ? (e.Properties[i] ?? "").Trim() : "";
        var summary = FirstLine(e.Message);

        if (string.Equals(e.Channel, ApplicationChannel, StringComparison.OrdinalIgnoreCase))
        {
            if ((provider, e.EventId) is ("Application Error", 1000) or ("Application Hang", 1002))
            {
                var app = Prop(0);
                if (app.Length == 0) return [];
                var hang = e.EventId == 1002;
                return [new AlertSignal(AlertKinds.AppCrash, AlertLevel.Info, app.ToLowerInvariant(), app,
                    summary.Length > 0 ? summary : $"{app} {(hang ? "stopped responding" : "crashed")}.",
                    [new AlertFactItem("app", app), new AlertFactItem("what", hang ? "hang" : "crash")], source,
                    new AlertEscalation(settings.AppCrashRepeats, settings.AppCrashWindow, AlertLevel.Warning))];
            }
            return [];
        }

        switch (provider, e.EventId)
        {
            case ("Resource-Exhaustion-Detector", 2004):
                readLevelsNow = true;
                return [new AlertSignal(AlertKinds.LowMemory, AlertLevel.Warning, "", "Memory",
                    summary.Length > 0 ? summary : "Windows ran low on memory.", null, source)];
            case ("srv", 2013):
                readLevelsNow = true;
                return [];
            case ("disk", 7 or 51 or 153):
                return [new AlertSignal(AlertKinds.DiskErrors, AlertLevel.Warning, Prop(0), Prop(0),
                    summary.Length > 0 ? summary : "A disk reported an input/output error.", [new AlertFactItem("event", e.EventId.ToString())], source,
                    new AlertEscalation(3, TimeSpan.FromDays(1), AlertLevel.Critical))];
            case ("disk", 52):
                return [new AlertSignal(AlertKinds.SmartFailure, AlertLevel.Critical, Prop(0), Prop(0),
                    summary.Length > 0 ? summary : "A disk predicts that it will fail soon.", null, source)];
            case ("Ntfs", 55 or 98):
                var volume = e.Properties.Select(p => (p ?? "").Trim()).FirstOrDefault(LooksLikeVolume) ?? Prop(0);
                return [new AlertSignal(AlertKinds.FsCorruption, AlertLevel.Critical, volume, volume,
                    summary.Length > 0 ? summary : "Windows found file system corruption.", null, source)];
            case ("Kernel-Power", 41):
                var shutdown = new AlertSignal(AlertKinds.UnexpectedShutdown, AlertLevel.Warning, "", "",
                    "Windows restarted without shutting down cleanly (a crash, a power cut or a held power button).", null, source);
                // A battery that dies while the PC sleeps, or a held power button, is not a failing battery (event data 5 and 6).
                var asleep = Prop(5) is not ("" or "0" or "false" or "False");
                var button = Prop(6) is not ("" or "0");
                if (!asleep && !button && lastPower is { OnBattery: true, Percent: > 10 } p && e.TimeUtc >= p.TimeUtc && e.TimeUtc - p.TimeUtc <= PowerReadingMaxAge)
                    return [shutdown, new AlertSignal(AlertKinds.BatteryFailing, AlertLevel.Warning, "shutoff", "Battery",
                        $"The PC shut off on battery with about {p.Percent}% left.", [new AlertFactItem("percent_before", p.Percent.ToString()!)], source)];
                return [shutdown];
            case ("Kernel-Power", 86):
                return [new AlertSignal(AlertKinds.Overheating, AlertLevel.Warning, "", "",
                    summary.Length > 0 ? summary : "Windows reported a thermal or power event.", null, source)];
            case ("WER-SystemErrorReporting", 1001):
                var code = Prop(0).Split(' ', 2)[0];
                return [new AlertSignal(AlertKinds.Bluescreen, AlertLevel.Critical, code, code.Length > 0 ? $"Stop code {code}" : "",
                    summary.Length > 0 ? summary : "Windows stopped with a blue screen.", code.Length > 0 ? [new AlertFactItem("bugcheck", code)] : null, source)];
            case ("WindowsUpdateClient", 20):
                var title = Prop(1);
                var id = Prop(2).Length > 0 ? Prop(2) : title;
                return [new AlertSignal(AlertKinds.UpdateFailed, AlertLevel.Warning, id, title,
                    title.Length > 0 ? $"An update failed to install: {title}" : "An update failed to install.",
                    Prop(0).Length > 0 ? [new AlertFactItem("error", Prop(0))] : null, source)];
        }
        return [];
    }

    /// <summary>
    /// Low disk space on one drive. Raised under the setting's GB, or under its percent while also under four times the GB (so a big
    /// drive isn't flagged with hundreds of GB free). Critical under 2 GB. Clears with a margin, so it doesn't flap.
    /// </summary>
    public static (LevelDecision Decision, AlertSignal? Signal) Disk(DiskReading d, AlertSettings s, bool open)
    {
        if (d.TotalGb < 1) return (LevelDecision.None, null); // recovery and boot partitions
        var percent = d.FreeGb / d.TotalGb * 100;
        var low = d.FreeGb < s.LowDiskFreeGb || (percent < s.LowDiskFreePercent && d.FreeGb < 4 * s.LowDiskFreeGb);
        if (low)
        {
            var level = d.FreeGb < AlertSettings.CriticalFreeGb ? AlertLevel.Critical : AlertLevel.Warning;
            return (LevelDecision.Raise, new AlertSignal(AlertKinds.LowDisk, level, d.Drive, d.Drive,
                $"Drive {d.Drive} has {d.FreeGb:0.#} GB free of {d.TotalGb:0} GB ({percent:0}%).",
                [new AlertFactItem("free_gb", d.FreeGb.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture)),
                 new AlertFactItem("free_percent", percent.ToString("0", System.Globalization.CultureInfo.InvariantCulture))]));
        }
        var recovered = d.FreeGb >= s.LowDiskFreeGb + 1 && (percent >= s.LowDiskFreePercent + 2 || d.FreeGb >= 4 * s.LowDiskFreeGb + 2);
        return (open && recovered ? LevelDecision.Clear : LevelDecision.None, null);
    }

    /// <summary>Memory commit charge. Raised on two readings in a row at or over the setting; clears 5 points under it.</summary>
    public static (LevelDecision Decision, AlertSignal? Signal) Memory(double commitPercent, bool previousHigh, AlertSettings s, bool open)
    {
        if (commitPercent >= s.MemoryCommitPercent)
            return previousHigh
                ? (LevelDecision.Raise, new AlertSignal(AlertKinds.LowMemory, AlertLevel.Warning, "", "Memory",
                    $"{commitPercent:0}% of the PC's memory (including the page file) is in use.",
                    [new AlertFactItem("commit_percent", commitPercent.ToString("0", System.Globalization.CultureInfo.InvariantCulture))]))
                : (LevelDecision.None, null);
        return (open && commitPercent < s.MemoryCommitPercent - 5 ? LevelDecision.Clear : LevelDecision.None, null);
    }

    /// <summary>
    /// A battery that stops charging: plugged in, under 50% (above that it may be a charge limit the maker set), not charging, and
    /// no higher than half an hour earlier.
    /// </summary>
    public static AlertSignal? NotCharging(PowerReading now, PowerReading? earlier)
    {
        if (!now.HasBattery || now.OnBattery || now.Charging || now.Percent is not { } p || p >= 50) return null;
        if (earlier is not { HasBattery: true, OnBattery: false, Charging: false, Percent: { } before }) return null;
        if (now.TimeUtc - earlier.TimeUtc < TimeSpan.FromMinutes(30) || p > before) return null;
        return new AlertSignal(AlertKinds.BatteryFailing, AlertLevel.Warning, "charging", "Battery",
            $"The battery stays at {p}% while plugged in and is not charging.", [new AlertFactItem("percent", p.ToString())]);
    }

    /// <summary>"Microsoft-Windows-Kernel-Power" → "Kernel-Power".</summary>
    public static string ShortProvider(string? provider)
    {
        const string prefix = "Microsoft-Windows-";
        var p = (provider ?? "").Trim();
        return p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? p[prefix.Length..] : p;
    }

    private static bool LooksLikeVolume(string p) => p.Length >= 2 && p[1] == ':' && char.IsLetter(p[0]);

    private static string FirstLine(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return "";
        var line = message.Trim().Split('\n', 2)[0].Trim();
        return line.Length <= 300 ? line : line[..300];
    }
}

/// <summary>
/// The alert as the Agent writes it to the app's own Windows log (event <see cref="Logging.LogEventIds.Alert"/>), so the app, which
/// never runs as admin, can read the PC's alerts.
/// </summary>
public static class AlertEventText
{
    public static string Format(AlertRecord a) => string.Join(Environment.NewLine,
        $"Alert: {a.Kind}",
        $"Level: {a.Level}",
        $"Status: {a.Status}",
        $"Instance: {a.InstanceLabel}",
        $"Count: {a.Count}",
        $"First seen: {a.FirstSeenUtc:O}",
        $"Last seen: {a.LastSeenUtc:O}",
        $"Summary: {a.Summary}",
        $"Related checks: {string.Join(", ", a.RelatedChecks)}",
        $"Alert id: {a.AlertId}");
}
