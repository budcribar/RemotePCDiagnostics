using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Usb;

/// <summary>A USB device that arrived while the port check was watching: where it was plugged in and how fast it connected.</summary>
public sealed record UsbArrival(DateTimeOffset At, string DeviceId, string Name, string PortKey, string Where, UsbSpeed Speed, bool Usb4,
    bool Downgraded, int ProblemCode, string? PortStatus)
{
    public bool Works => ProblemCode == 0 && (PortStatus is null || !UsbPortStatus.IsFailure(PortStatus));
}

/// <param name="Arrivals">Every device plugged in while watching, oldest first.</param>
/// <param name="Drops">Several devices behind one hub or dock that went away at the same moment.</param>
/// <param name="EveryDeviceWorked">The person's answer to "Did every device work?"; null until they answer.</param>
/// <param name="Watching">The check is still watching for devices (the person hasn't pressed Finish).</param>
public sealed record UsbPortCheckReport(IReadOnlyList<UsbArrival> Arrivals, IReadOnlyList<UsbDrop> Drops, bool? EveryDeviceWorked,
    bool Watching, string? Notice = null)
{
    public static UsbPortCheckReport Empty { get; } = new([], [], null, false);

    /// <summary>Each port that saw a device, once, with the last device seen on it.</summary>
    public IReadOnlyList<UsbArrival> PortsTested => [.. Arrivals.GroupBy(a => a.PortKey, StringComparer.OrdinalIgnoreCase).Select(g => g.Last())];
}

/// <summary>The interactive USB port check: its result for each state, and how it notices devices arriving.</summary>
public static class UsbPortCheck
{
    public const string WaitingMessage = "Plug a USB stick or mouse into each port in turn, then press Finish.";
    public const string AskMessage = "Did every device work? Choose Yes or No.";

    /// <summary>How often the tree is read while watching.</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    /// <summary>The longest one watch lasts; the person can start it again.</summary>
    public static readonly TimeSpan MaxWatch = TimeSpan.FromMinutes(15);

    public static (DiagnosticStatus Status, string Message) Outcome(UsbPortCheckReport r)
    {
        var ports = r.PortsTested.Count;
        var broken = r.PortsTested.Count(a => !a.Works);
        var slow = r.PortsTested.Count(a => a.Downgraded);
        string Ports() => ports == 1 ? "1 port" : $"{ports} ports";
        if (r.Watching) return (DiagnosticStatus.Running, ports == 0 ? WaitingMessage : $"{Ports()} tested so far. Keep going, then press Finish.");
        if (r.EveryDeviceWorked is null) return (DiagnosticStatus.Warning, ports == 0 ? "No device was plugged in. " + AskMessage : $"{Ports()} tested. " + AskMessage);
        if (r.EveryDeviceWorked == false) return (DiagnosticStatus.Error, $"Failed: the person reported a port or device that didn't work ({Ports()} tested).");
        if (broken > 0) return (DiagnosticStatus.Error, $"Failed: {broken} of {Ports()} had a device that didn't start.");
        if (slow > 0 || r.Drops.Count > 0)
            return (DiagnosticStatus.Warning, $"Passed with warnings: {Ports()} tested"
                + (slow > 0 ? $", {slow} at USB 2 speed with a USB 3 device" : "")
                + (r.Drops.Count > 0 ? $", {r.Drops.Count} dock or hub dropped several devices at once" : "") + ".");
        return ports == 0 ? (DiagnosticStatus.Warning, "No port was tested.") : (DiagnosticStatus.Ok, $"Passed: {Ports()} tested, every device worked.");
    }

    public static DiagnosticResult ToResult(UsbPortCheckReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<UsbPortCheckReport>(ModuleSlugs.UsbPortCheck, status, msg, DateTimeOffset.Now, r);
    }

    /// <summary>The latest result with the person's answer; null when there's no finished watch to answer for.</summary>
    public static DiagnosticResult? Answer(DiagnosticResult latest, bool everyDeviceWorked) =>
        latest.Payload is UsbPortCheckReport { Watching: false } r ? ToResult(r with { EveryDeviceWorked = everyDeviceWorked }) : null;

    /// <summary>The devices in <paramref name="after"/> that weren't in <paramref name="before"/>, each with its port and speed.</summary>
    public static IReadOnlyList<UsbArrival> Arrivals(UsbSnapshot before, UsbSnapshot after, DateTimeOffset at)
    {
        if (before.Error is not null || after.Error is not null) return [];
        var had = before.Nodes.Select(n => n.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. UsbAnalysis.Devices(after).Where(d => d.Node.Kind == UsbNodeKind.Device && !had.Contains(d.Node.Id)).Select(d => new UsbArrival(at,
            d.Node.Id, d.Node.Name, PortKey(d), d.Where, d.Speed, d.Usb4, d.Downgraded, d.Node.ProblemCode, d.Port?.Status))];
    }

    /// <summary>A port's identity: its hub and number. A USB 3 port's USB 2 half is the same connector, so it keys on the lower of the two.</summary>
    public static string PortKey(UsbDeviceView d)
    {
        var hub = d.Hub?.Id ?? "?";
        var n = d.Port?.Number ?? d.Node.Port ?? 0;
        if (d.Port?.CompanionPort is { } other && other > 0 && other < n) n = other;
        return hub + "#" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}

/// <summary>What the Interactive tests page asks of the USB port check module: its live watch, Finish and Cancel.</summary>
public interface IUsbPortCheckModule : IDiagnosticModule
{
    /// <summary>What the check has seen so far in this watch.</summary>
    UsbPortCheckReport Live { get; }
    /// <summary>Raised when a device arrives or drops while watching.</summary>
    event EventHandler? Changed;
    /// <summary>Stops watching; the run ends and asks whether every device worked.</summary>
    void Finish();
    void Cancel();
}
