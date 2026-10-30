using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery row from osquery <c>battery</c>.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount)
{
    public static BatteryStatus FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("model"), r.Str("manufacturer"), r.Str("chemistry"), r.Str("state"),
        r.Int("percent_remaining"), r.Int("designed_capacity"), r.Int("max_capacity"), r.Int("cycle_count"));

    public int? HealthPercent => DesignCapacity is > 0 && MaxCapacity is > 0
        ? (int)Math.Round(Math.Clamp(MaxCapacity.Value * 100.0 / DesignCapacity.Value, 0, 120))
        : null;

    public int? WearPercent => HealthPercent is { } h ? Math.Max(0, 100 - h) : null;
}

/// <summary>
/// Battery health (wear level, cycle count, charge state via osquery <c>battery</c>) and active Windows power plan
/// (<c>powercfg /getactivescheme</c>).
/// </summary>
public sealed class BatteryPowerModule(OsqueryRunner runner, SystemCommandRunner? commands = null) : OsqueryAreaModuleBase(runner)
{
    public const string ModuleName = "BatteryPower";
    public const string BatterySql = "SELECT * FROM battery;";
    public const int LowBatteryHealthPercent = 70;

    public override string Name => ModuleName;
    public override string DisplayName => "Battery & power plan";
    protected override string FailedMessage => "Couldn't read battery and power settings on this PC.";

    public static string PowerCfg => SystemCommandRunner.SystemTool("powercfg.exe");

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking battery health and power plan…");
        var batQ = await QueryAsync(BatterySql, ct).ConfigureAwait(false);
        string? plan = null;
        if (commands is not null)
        {
            var pr = await commands.RunAsync(PowerCfg, ["/getactivescheme"], ct).ConfigureAwait(false);
            if (pr is { ExitCode: 0 }) plan = ParsePowerPlan(pr.StdOut);
        }

        if (!batQ.Success && plan is null) return AreaReport.Failed(FailedMessage);
        var batteries = batQ.Success ? batQ.Rows!.Select(BatteryStatus.FromRow).ToList() : null;
        return Build(batteries, plan);
    }

    public static string? ParsePowerPlan(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var open = stdout.LastIndexOf('(');
        var close = stdout.LastIndexOf(')');
        if (open >= 0 && close > open + 1)
            return stdout[(open + 1)..close].Trim();
        return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
    }

    public static AreaReport Build(IReadOnlyList<BatteryStatus>? batteries, string? powerPlan)
    {
        if (batteries is null && powerPlan is null) return AreaReport.Failed("Couldn't read battery and power settings on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();

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
            var level = worn ? AreaLevel.Warning : AreaLevel.Ok;
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
            parts.Add(health is { } h2 ? $"Battery health {h2}%" + (b.PercentRemaining is { } pr ? $" ({pr}%)" : "") : "Battery present");
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
            ]));
        if (!string.IsNullOrWhiteSpace(powerPlan)) parts.Add($"{planName} plan");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }
}
