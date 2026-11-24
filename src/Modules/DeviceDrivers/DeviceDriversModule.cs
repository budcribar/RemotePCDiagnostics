using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Device Manager problems (devices with a non-zero <c>ConfigManagerErrorCode</c>) and hardware driver versions, read from
/// <paramref name="source"/> (WMI in the app, osquery and PowerShell in the Store edition without an Agent).
/// </summary>
public sealed class DeviceDriversModule(IDeviceDriverSource source, SystemCommandRunner? commands = null, ILogger? log = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.DeviceDrivers;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DeviceDrivers;
    public override string DisplayName => "Device Manager & drivers";
    protected override string FailedMessage => "Couldn't check Device Manager and drivers on this PC.";

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => source.CheckAvailabilityAsync(cancellationToken);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        // Asked alongside the other reads; scripted test runners aren't asked.
        var pendingRead = commands is { IsScripted: false } ? PendingUpdates.ReadAsync(commands, ct) : null;
        progress.ReportStep(1, 2, "Checking Device Manager for problem devices…");
        var problems = await source.ReadProblemDevicesAsync(ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Reading hardware drivers…");
        var drivers = await source.ReadDriversAsync(ct).ConfigureAwait(false);
        var report = Build(problems, drivers);
        if (pendingRead is null) return report;
        PendingUpdateList? pending = null;
        try { pending = await pendingRead.ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogWarn($"{Name}: pending driver updates unreadable: {ex.Message}"); }
        return WithPendingUpdates(report, pending);
    }

    /// <summary>Adds the pending-driver-updates card. It never changes the check's result.</summary>
    public static AreaReport WithPendingUpdates(AreaReport report, PendingUpdateList? pending) =>
        report.Cards.Count == 0 ? report : report with { Cards = [.. report.Cards, PendingUpdates.Card(pending, drivers: true)] };

    private static readonly HashSet<string> KeyClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "DISPLAY", "NET", "MEDIA", "HDC", "SCSIADAPTER", "NVME", "USB", "BLUETOOTH", "CAMERA", "IMAGE", "BIOMETRIC", "HIDCLASS",
    };

    public static AreaReport Build(IReadOnlyList<ProblemDevice>? problems, IReadOnlyList<DriverEntry>? drivers)
    {
        if (problems is null && drivers is null) return AreaReport.Failed("Couldn't check Device Manager and drivers on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        if (problems is null)
            cards.Add(AreaCard.Failed("problems", "Device Manager problems", "Couldn't read Device Manager status."));
        else
        {
            var ordered = problems.OrderBy(p => p.IsDisabledOnly).ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
            var faulting = ordered.Where(p => !p.IsDisabledOnly).ToList();
            var disabled = ordered.Where(p => p.IsDisabledOnly).ToList();
            var level = faulting.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok;
            var headline = ordered.Count == 0 ? "All devices working"
                : faulting.Count > 0 && disabled.Count > 0 ? $"{Plural(faulting.Count, "device")} with a problem, {disabled.Count} disabled"
                : faulting.Count > 0 ? $"{Plural(faulting.Count, "device")} with a problem"
                : $"{Plural(disabled.Count, "disabled device")}";

            var rows = ordered
                .Select(p => new AreaRow(
                    p.IsDisabledOnly ? AreaLevel.Neutral : AreaLevel.Warning,
                    [p.Name, p.Class.Length > 0 ? p.Class : "Other", p.FriendlyError],
                    Actions: p.DeviceId.Length > 0
                        ? [new AreaAction(p.IsDisabledOnly ? RemediationKind.EnableDevice : RemediationKind.RestartDevice,
                            p.IsDisabledOnly ? "Enable device" : "Restart device", p.DeviceId, p.Name)]
                        : null)).ToList();

            var metaItems = ordered.Take(3).Select(p => $"{p.Name} ({p.FriendlyError})").ToList();
            if (ordered.Count > 3) metaItems.Add($"+{ordered.Count - 3} more");
            if (rows.Any(r => r.Actions is { Count: > 0 })) metaItems.Add("Click to inspect and fix");
            var meta = ordered.Count == 0 ? "No Device Manager errors or missing drivers"
                : string.Join(" · ", metaItems);

            cards.Add(new("problems", "Device Manager problems", level, headline, meta,
                ["Device", "Category", "Problem"], rows,
                EmptyText: "No devices with problems were reported by Windows.",
                Actions:
                [
                    new(RemediationKind.CheckAndInstallDriverUpdates, "Check & install driver updates"),
                    new(RemediationKind.ScanHardwareChanges, "Scan for hardware changes"),
                ]));

            parts.Add(ordered.Count == 0 ? "All devices working"
                : faulting.Count > 0 && disabled.Count > 0 ? $"{Plural(faulting.Count, "device problem")}, {disabled.Count} disabled"
                : faulting.Count > 0 ? $"{Plural(faulting.Count, "device problem")}"
                : $"{Plural(disabled.Count, "disabled device")}");
        }

        if (drivers is null)
            cards.Add(AreaCard.Failed("drivers", "Hardware drivers", "Couldn't read installed drivers."));
        else
        {
            var distinct = drivers.Where(d => d.DeviceName.Length > 0)
                .DistinctBy(d => (d.DeviceName.ToUpperInvariant(), d.Version))
                .OrderByDescending(d => KeyClasses.Contains(d.Class))
                .ThenBy(d => d.Class, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(d => d.DeviceName, StringComparer.CurrentCultureIgnoreCase).ToList();
            var unsigned = distinct.Where(d => !d.Signed).ToList();
            var level = unsigned.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok;

            cards.Add(new("drivers", "Hardware drivers", level,
                Plural(distinct.Count, "driver"),
                unsigned.Count > 0 ? $"{Plural(unsigned.Count, "unsigned driver")} · click to inspect" : "All reported drivers are signed",
                ["Device", "Category", "Provider", "Version", "Date"],
                distinct.Select(d => new AreaRow(d.Signed ? AreaLevel.Neutral : AreaLevel.Warning,
                    [d.DeviceName, d.Class, d.Provider, d.Version, OsqueryDates.Format(d.Date)],
                    [null, null, null, null, OsqueryDates.SortKey(d.Date)])).ToList(),
                EmptyText: "No drivers were reported."));

            parts.Add(Plural(distinct.Count, "driver") + (unsigned.Count > 0 ? $" ({unsigned.Count} unsigned)" : ""));
        }

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }
}
