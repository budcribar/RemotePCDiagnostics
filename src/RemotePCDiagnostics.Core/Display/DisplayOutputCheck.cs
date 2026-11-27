using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Display;

/// <summary>
/// A monitor that appeared on a video output while the output check was watching, kept up to date while it stays connected (Windows may
/// take a moment to show the desktop on it). <see cref="PictureAppeared"/> is the person's answer to "Did the picture appear?"; null until
/// they answer.
/// </summary>
public sealed record DisplayArrival(DateTimeOffset At, string Key, string Monitor, string Connector, string Adapter, bool Active,
    string Mode, double? RefreshHz, string? EdidProblem, bool BelowNative, bool? PictureAppeared = null, int Unplugged = 0)
{
    /// <summary>The monitor came and went more than once while watching: a loose cable or connector.</summary>
    public bool Flapping => Unplugged >= 2;
}

/// <summary>An output the person says they plugged a monitor into and nothing showed up for.</summary>
public sealed record DisplayNoSignal(DateTimeOffset At, string Port);

/// <param name="Arrivals">Each output a monitor arrived on while watching, once, oldest first.</param>
/// <param name="NoSignal">Ports the person reported with no picture and no monitor seen.</param>
/// <param name="Watching">The check is still watching (the person hasn't pressed Finish).</param>
public sealed record DisplayOutputCheckReport(IReadOnlyList<DisplayArrival> Arrivals, IReadOnlyList<DisplayNoSignal> NoSignal, bool Watching,
    string? Notice = null)
{
    public static DisplayOutputCheckReport Empty { get; } = new([], [], false);

    /// <summary>Arrivals still waiting for "Did the picture appear?".</summary>
    public int Unanswered => Arrivals.Count(a => a.PictureAppeared is null);
}

/// <summary>The interactive video output check: its result for each state, and how it notices monitors arriving.</summary>
public static class DisplayOutputCheck
{
    public const string WaitingMessage = "Plug a monitor into each video port in turn (HDMI, DisplayPort, USB-C, VGA, the dock's), then press Finish.";
    public const string AskMessage = "Did the picture appear on each? Answer Yes or No for every port.";

    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan MaxWatch = TimeSpan.FromMinutes(15);

    private static string Ports(int n) => n == 1 ? "1 port" : $"{n} ports";

    public static (DiagnosticStatus Status, string Message) Outcome(DisplayOutputCheckReport r)
    {
        var ports = r.Arrivals.Count;
        var no = r.Arrivals.Count(a => a.PictureAppeared == false);
        if (r.Watching)
            return (DiagnosticStatus.Running, ports == 0 && r.NoSignal.Count == 0 ? WaitingMessage
                : $"{Ports(ports)} seen so far" + (r.NoSignal.Count > 0 ? $", {r.NoSignal.Count} with nothing" : "") + ". Keep going, then press Finish.");
        if (no > 0 || r.NoSignal.Count > 0)
        {
            var bits = new List<string>();
            if (no > 0) bits.Add(no == 1 ? "1 port showed no picture" : $"{no} ports showed no picture");
            if (r.NoSignal.Count > 0) bits.Add(r.NoSignal.Count == 1 ? "1 port never saw the monitor" : $"{r.NoSignal.Count} ports never saw the monitor");
            return (DiagnosticStatus.Error, "Failed: " + string.Join(", ", bits) + $" ({Ports(ports + r.NoSignal.Count)} tried).");
        }
        if (ports == 0) return (DiagnosticStatus.Warning, "No monitor was plugged in.");
        if (r.Unanswered > 0) return (DiagnosticStatus.Warning, $"{Ports(ports)} tested. " + AskMessage);
        var edid = r.Arrivals.Count(a => a.EdidProblem is not null);
        var low = r.Arrivals.Count(a => a.BelowNative);
        var flaps = r.Arrivals.Count(a => a.Flapping);
        if (edid > 0 || low > 0 || flaps > 0)
            return (DiagnosticStatus.Warning, $"Passed with warnings: {Ports(ports)} showed a picture"
                + (edid > 0 ? $", {edid} with a missing or damaged EDID" : "")
                + (low > 0 ? $", {low} below the monitor's native resolution" : "")
                + (flaps > 0 ? $", {flaps} dropped and came back" : "") + ".");
        return (DiagnosticStatus.Ok, $"Passed: {Ports(ports)} tested, the picture appeared on each.");
    }

    public static DiagnosticResult ToResult(DisplayOutputCheckReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<DisplayOutputCheckReport>(ModuleSlugs.DisplayOutputCheck, status, msg, DateTimeOffset.Now, r);
    }

    /// <summary>The report with the person's answer for one port.</summary>
    public static DisplayOutputCheckReport WithAnswer(DisplayOutputCheckReport r, string key, bool pictureAppeared) =>
        r with { Arrivals = [.. r.Arrivals.Select(a => a.Key == key ? a with { PictureAppeared = pictureAppeared } : a)] };

    /// <summary>The report with a port the person says showed nothing at all.</summary>
    public static DisplayOutputCheckReport WithNoSignal(DisplayOutputCheckReport r, string port, DateTimeOffset at) =>
        r with { NoSignal = [.. r.NoSignal, new DisplayNoSignal(at, string.IsNullOrWhiteSpace(port) ? "A video port" : port.Trim())] };

    /// <summary>The latest finished result with the person's answer; null when there's no finished watch to answer for.</summary>
    public static DiagnosticResult? Answer(DiagnosticResult latest, string key, bool pictureAppeared) =>
        latest.Payload is DisplayOutputCheckReport { Watching: false } r && r.Arrivals.Any(a => a.Key == key) ? ToResult(WithAnswer(r, key, pictureAppeared)) : null;

    /// <summary>The latest finished result with a port that showed nothing; null when there's no finished watch.</summary>
    public static DiagnosticResult? NoSignal(DiagnosticResult latest, string port) =>
        latest.Payload is DisplayOutputCheckReport { Watching: false } r ? ToResult(WithNoSignal(r, port, DateTimeOffset.Now)) : null;

    private static DisplayArrival From(DisplayOutput o, DisplaySnapshot all, DateTimeOffset at) =>
        new(at, o.Key, Displays.Name(o), Displays.Where(o, all), o.AdapterName ?? "", o.Active,
            o.Active ? Displays.Mode(o.Width, o.Height) : "", o.Active ? o.RefreshHz : null, Displays.EdidProblem(o), Displays.BelowNative(o));

    /// <summary>
    /// The report after one more read: monitors on outputs that had none in <paramref name="before"/> are added (or, for an output seen
    /// before, counted again); each one still connected is refreshed (it may have just become active), and one that went away counts an unplug.
    /// </summary>
    public static IReadOnlyList<DisplayArrival> Next(IReadOnlyList<DisplayArrival> arrivals, DisplaySnapshot before, DisplaySnapshot now, DateTimeOffset at)
    {
        if (before.Error is not null || now.Error is not null) return arrivals;
        var had = before.Monitors.Select(o => o.Key).ToHashSet(StringComparer.Ordinal);
        var has = now.Monitors.ToDictionary(o => o.Key, StringComparer.Ordinal);
        var list = new List<DisplayArrival>();
        foreach (var a in arrivals)
        {
            if (has.TryGetValue(a.Key, out var o))
            {
                var fresh = From(o, now, a.At);
                list.Add(fresh with { PictureAppeared = a.PictureAppeared, Unplugged = a.Unplugged });
            }
            else list.Add(had.Contains(a.Key) ? a with { Active = false, Unplugged = a.Unplugged + 1 } : a);
        }
        foreach (var o in now.Monitors.Where(o => !had.Contains(o.Key) && arrivals.All(a => a.Key != o.Key)))
            list.Add(From(o, now, at));
        return list;
    }
}

/// <summary>What the Interactive tests page asks of the video output check module: its live watch, the answers, Finish and Cancel.</summary>
public interface IDisplayOutputCheckModule : IDiagnosticModule
{
    DisplayOutputCheckReport Live { get; }
    /// <summary>Raised when a monitor arrives, goes, or changes while watching.</summary>
    event EventHandler? Changed;
    /// <summary>Records "Did the picture appear?" for one port while watching.</summary>
    void Answer(string key, bool pictureAppeared);
    /// <summary>Records a port where the person plugged a monitor in and nothing was seen.</summary>
    void ReportNoSignal(string port);
    void Finish();
    void Cancel();
}
