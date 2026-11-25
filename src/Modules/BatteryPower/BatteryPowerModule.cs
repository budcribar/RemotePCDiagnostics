using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Battery health (wear level, cycle count, charge state) and the active Windows power plan, read from <paramref name="source"/>: WMI through
/// the Agent in the app, and in the Store edition the legacy osquery + powercfg reader when no Agent is connected.
/// </summary>
public sealed class BatteryPowerModule(IBatteryPowerSource source, ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.BatteryPower;
    public const int LowBatteryHealthPercent = BatteryStatus.LowHealthPercent;
    public const int PerformanceLimitWarningThreshold = 90;
    public static readonly TimeSpan ConfirmationDelay = TimeSpan.FromSeconds(5);

    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BatteryPower;
    public override string DisplayName => "Battery & power plan";
    protected override string FailedMessage => "Couldn't read battery and power settings on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking battery health…");
        var batteries = await source.ReadBatteriesAsync(ct).ConfigureAwait(false);
        var perf = await source.ReadProcessorPerformanceAsync(ct).ConfigureAwait(false);

        var onAc1 = IsOnAcPower(batteries);
        var discharging1 = batteries is { Count: > 0 } && batteries.Any(b => b.IsDischargingOnAc);
        var heldBack1 = onAc1 && perf?.PerformanceLimitPercent is > 0 and < PerformanceLimitWarningThreshold;

        var confirmedDischargingOnAc = false;
        var confirmedHeldBackOnAc = false;

        // Fast path: only wait 5 s for a second confirmation sample when the first sample looks suspicious.
        if (discharging1 || heldBack1)
        {
            progress.ReportStep(1, 2, "Confirming power and processor limit…");
            await _delay(ConfirmationDelay, ct).ConfigureAwait(false);

            if (discharging1)
            {
                var batteries2 = await source.ReadBatteriesAsync(ct).ConfigureAwait(false);
                if (batteries2 is not null) batteries = batteries2;
                confirmedDischargingOnAc = batteries2 is { Count: > 0 } && batteries2.Any(b => b.IsDischargingOnAc);
            }

            if (heldBack1)
            {
                var perf2 = await source.ReadProcessorPerformanceAsync(ct).ConfigureAwait(false);
                var onAc2 = IsOnAcPower(batteries);
                confirmedHeldBackOnAc = onAc2 && perf2?.PerformanceLimitPercent is > 0 and < PerformanceLimitWarningThreshold;
                if (perf2 is not null) perf = perf2;
            }
        }

        progress.ReportStep(2, 2, "Checking active power plan…");
        var plan = await source.ReadActivePlanAsync(ct).ConfigureAwait(false);
        var policy = await source.ReadPowerPolicyAsync(ct).ConfigureAwait(false);
        if (batteries is null && plan is null) return AreaReport.Failed(FailedMessage);
        return Build(batteries, plan, confirmedDischargingOnAc, confirmedHeldBackOnAc, perf, policy);
    }

    private static bool IsOnAcPower(IReadOnlyList<BatteryStatus>? batteries) =>
        batteries is { Count: > 0 } ? batteries.Any(b => b.IsOnAc) : batteries is not null;

    public static AreaReport Build(
        IReadOnlyList<BatteryStatus>? batteries,
        string? powerPlan,
        bool dischargingOnAc = false,
        bool heldBackOnAc = false,
        ProcessorPerformanceSample? processorPerf = null,
        PowerPolicySnapshot? policy = null)
    {
        if (batteries is null && powerPlan is null) return AreaReport.Failed("Couldn't read battery and power settings on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();
        var metrics = new List<KeyMetric>();

        if (batteries is null)
            cards.Add(AreaCard.Failed("battery", "Battery health", "Couldn't read battery details."));
        else if (batteries.Count == 0)
        {
            cards.Add(new("battery", "Battery health", AreaLevel.Neutral, "No battery (desktop / AC only)",
                "This PC runs directly on wall power", ["Detail", "Value"],
                [new(AreaLevel.Neutral, ["Power source", "AC power (no battery installed)"])]));
            parts.Add("No battery (AC power)");
        }
        else
        {
            var b = batteries[0];
            var health = b.HealthPercent;
            var worn = health is < LowBatteryHealthPercent;
            // Health the battery didn't report is no reason to call it good.
            var healthLevel = worn ? AreaLevel.Warning : health is null ? AreaLevel.Neutral : AreaLevel.Ok;
            var level = dischargingOnAc ? AreaLevel.Warning : healthLevel;
            var headline = dischargingOnAc
                ? "Plugged in, but battery is discharging"
                : health is { } h ? $"{h}% battery health" : (b.State.Length > 0 ? b.State : "Battery present");
            var metaParts = new List<string>();
            if (b.CycleCount is > 0) metaParts.Add($"{b.CycleCount} cycles");
            var model = string.Join(" ", new[] { b.Manufacturer, b.Model }.Where(x => x.Length > 0));
            if (model.Length > 0) metaParts.Add(model);
            else if (b.Chemistry.Length > 0) metaParts.Add(b.Chemistry);

            var rows = new List<AreaRow>();
            void Add(string l, string? v, AreaLevel lv = AreaLevel.Neutral) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(lv, [l, v])); }
            Add("Power state", b.State, dischargingOnAc ? AreaLevel.Warning : AreaLevel.Neutral);
            if (dischargingOnAc)
                Add("Charger warning", b.DischargeRateMw is > 0
                    ? $"Battery is draining ({b.DischargeRateMw.Value / 1000.0:0.0} W) while plugged in"
                    : "Battery is draining while plugged in", AreaLevel.Warning);
            Add("Current charge", b.PercentRemaining is { } p ? $"{p}%" : null);
            Add("Estimated battery health", health is { } hp ? $"{hp}% of original capacity ({b.WearPercent}% wear)" : "Not reported", healthLevel);
            Add("Design capacity", b.DesignCapacity is > 0 ? $"{b.DesignCapacity.Value.ToString("N0", CultureInfo.InvariantCulture)} mWh" : null);
            Add("Full charge capacity", b.MaxCapacity is > 0 ? $"{b.MaxCapacity.Value.ToString("N0", CultureInfo.InvariantCulture)} mWh" : null);
            Add("Cycle count", b.CycleCount is > 0 ? b.CycleCount.Value.ToString("N0", CultureInfo.InvariantCulture) : "Not reported");
            Add("Battery model", string.Join(" ", new[] { b.Manufacturer, b.Model }.Where(x => x.Length > 0)));
            Add("Chemistry", b.Chemistry);

            var notes = new List<string>();
            if (dischargingOnAc)
                notes.Add("This PC is plugged in, yet the battery is still draining. Check the charger wattage or USB-C dock — an under-wattage adapter can cause severe slowdowns.");
            if (worn)
                notes.Add("A battery below 70% health holds significantly less charge than when new and may need replacement.");

            cards.Add(new("battery", "Battery health", level, headline, string.Join(" · ", metaParts), ["Detail", "Value"], rows,
                Note: notes.Count > 0 ? string.Join(" ", notes) : null));
            // Tracked over time: health falling (or capacity dropping) faster than normal is the early sign of a battery to replace.
            metrics.AddRange(CheckKeyMetrics.Battery(b));
            parts.Add(dischargingOnAc
                ? "Plugged in, discharging"
                : health is { } h2 ? $"Battery health {h2}%" + (b.PercentRemaining is { } pr ? $" · {pr}% charged" : "") : "Battery present");
        }

        var planName = string.IsNullOrWhiteSpace(powerPlan) ? "Not reported" : powerPlan.Trim();
        var isSaver = planName.Contains("Power saver", StringComparison.OrdinalIgnoreCase) || planName.Contains("Energy Saver", StringComparison.OrdinalIgnoreCase);
        var acCap = policy?.AcMaxProcessorStatePercent is >= 0 and <= 100 and var capVal ? capVal : (int?)null;
        var hasAcCapWarning = acCap is < 100;
        var planRows = new List<AreaRow>
        {
            new(isSaver ? AreaLevel.Warning : AreaLevel.Ok, ["Active power plan", planName]),
        };
        if (policy?.PowerMode is { Length: > 0 } powerMode)
            planRows.Add(new(AreaLevel.Neutral, ["Power mode", powerMode]));
        if (acCap is { } configuredCap)
        {
            var capText = configuredCap < 100
                ? $"Configured maximum processor state on AC is {configuredCap}%"
                : "100%";
            planRows.Add(new(hasAcCapWarning ? AreaLevel.Warning : AreaLevel.Ok, ["Configured maximum processor state (AC)", capText]));
        }
        if (heldBackOnAc && processorPerf?.PerformanceLimitPercent is { } perfLimit)
        {
            planRows.Add(new(AreaLevel.Warning, ["Processor performance limit (AC)", $"{perfLimit}% — The processor is being held back while plugged in (weak charger, dock or heat)."]));
        }
        planRows.Add(new(AreaLevel.Neutral, ["Impact", isSaver ? "Power saver caps processor clock speeds and can make the PC feel slow." : "Normal processor speed scaling enabled."]));

        var planLevel = (isSaver || hasAcCapWarning || heldBackOnAc) ? AreaLevel.Warning : AreaLevel.Ok;
        var planNotes = new List<string>();
        if (heldBackOnAc)
            planNotes.Add("The processor is being held back while plugged in (weak charger, dock or heat).");
        if (hasAcCapWarning)
            planNotes.Add($"Configured maximum processor state on AC is {acCap}%. This is a configured power-plan limit; effective behavior can also depend on Windows Power mode, Energy Saver, or OEM controls.");

        cards.Add(new("plan", "Windows power plan", planLevel, planName,
            isSaver ? "Power saver reduces CPU speed to save battery"
                : heldBackOnAc ? "Processor held back while plugged in"
                : hasAcCapWarning ? $"Configured maximum processor state on AC is {acCap}%"
                : "Active power scheme",
            ["Detail", "Value"],
            planRows,
            Note: planNotes.Count > 0 ? string.Join(" ", planNotes) : null,
            Actions: isSaver ? [new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced plan", RemediationService.BalancedPlanGuid, "Balanced power plan")] : null));
        if (!string.IsNullOrWhiteSpace(powerPlan)) parts.Add($"{planName} plan");
        if (heldBackOnAc) parts.Add("processor held back on AC");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status) { KeyMetrics = metrics.Count > 0 ? metrics : null };
    }
}
