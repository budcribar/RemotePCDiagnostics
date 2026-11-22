using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Battery health (wear level, cycle count, charge state) and the active Windows power plan, read from <paramref name="source"/>: WMI through
/// the Agent in the app, and in the Store edition the legacy osquery + powercfg reader when no Agent is connected.
/// </summary>
public sealed class BatteryPowerModule(IBatteryPowerSource source, ILogger? log = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.BatteryPower;
    public const int LowBatteryHealthPercent = BatteryStatus.LowHealthPercent;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BatteryPower;
    public override string DisplayName => "Battery & power plan";
    protected override string FailedMessage => "Couldn't read battery and power settings on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking battery health…");
        var batteries = await source.ReadBatteriesAsync(ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Checking active power plan…");
        var plan = await source.ReadActivePlanAsync(ct).ConfigureAwait(false);
        if (batteries is null && plan is null) return AreaReport.Failed(FailedMessage);
        return Build(batteries, plan);
    }

    public static AreaReport Build(IReadOnlyList<BatteryStatus>? batteries, string? powerPlan)
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
            var level = worn ? AreaLevel.Warning : health is null ? AreaLevel.Neutral : AreaLevel.Ok;
            var headline = health is { } h ? $"{h}% battery health" : (b.State.Length > 0 ? b.State : "Battery present");
            var metaParts = new List<string>();
            if (b.State.Length > 0) metaParts.Add(b.State);
            if (b.PercentRemaining is { } pct) metaParts.Add($"{pct}% charged");
            if (b.CycleCount is > 0) metaParts.Add($"{b.CycleCount} cycles");

            var rows = new List<AreaRow>();
            void Add(string l, string? v, AreaLevel lv = AreaLevel.Neutral) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(lv, [l, v])); }
            Add("Power state", b.State);
            Add("Current charge", b.PercentRemaining is { } p ? $"{p}%" : null);
            Add("Estimated battery health", health is { } hp ? $"{hp}% of original capacity ({b.WearPercent}% wear)" : "Not reported", level);
            Add("Design capacity", b.DesignCapacity is > 0 ? $"{b.DesignCapacity.Value.ToString("N0", CultureInfo.InvariantCulture)} mWh" : null);
            Add("Full charge capacity", b.MaxCapacity is > 0 ? $"{b.MaxCapacity.Value.ToString("N0", CultureInfo.InvariantCulture)} mWh" : null);
            Add("Cycle count", b.CycleCount is > 0 ? b.CycleCount.Value.ToString("N0", CultureInfo.InvariantCulture) : "Not reported");
            Add("Battery model", string.Join(" ", new[] { b.Manufacturer, b.Model }.Where(x => x.Length > 0)));
            Add("Chemistry", b.Chemistry);

            cards.Add(new("battery", "Battery health", level, headline, string.Join(" · ", metaParts), ["Detail", "Value"], rows,
                Note: worn ? "A battery below 70% health holds significantly less charge than when new and may need replacement." : null));
            // Tracked over time: health falling (or capacity dropping) faster than normal is the early sign of a battery to replace.
            metrics.AddRange(CheckKeyMetrics.Battery(b));
            parts.Add(health is { } h2 ? $"Battery health {h2}%" + (b.PercentRemaining is { } pr ? $" · {pr}% charged" : "") : "Battery present");
        }

        var planName = string.IsNullOrWhiteSpace(powerPlan) ? "Not reported" : powerPlan.Trim();
        var isSaver = planName.Contains("Power saver", StringComparison.OrdinalIgnoreCase) || planName.Contains("Energy Saver", StringComparison.OrdinalIgnoreCase);
        var planLevel = isSaver ? AreaLevel.Warning : AreaLevel.Ok;
        cards.Add(new("plan", "Windows power plan", planLevel, planName,
            isSaver ? "Power saver reduces CPU speed to save battery" : "Active power scheme",
            ["Detail", "Value"],
            [
                new(planLevel, ["Active power plan", planName]),
                new(AreaLevel.Neutral, ["Impact", isSaver ? "Power saver caps processor clock speeds and can make the PC feel slow." : "Normal processor speed scaling enabled."]),
            ],
            Actions: isSaver ? [new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced plan", RemediationService.BalancedPlanGuid, "Balanced power plan")] : null));
        if (!string.IsNullOrWhiteSpace(powerPlan)) parts.Add($"{planName} plan");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status) { KeyMetrics = metrics.Count > 0 ? metrics : null };
    }
}
