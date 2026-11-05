using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One Windows service (osquery <c>services</c>).</summary>
public sealed record ServiceInfo(string Name, string DisplayName, string Status, string StartType, string Account, string Description)
{
    public static ServiceInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("name"), r.Str("display_name"), r.Str("status"), r.Str("start_type"), r.Str("user_account"), r.Str("description"));

    public string Label => DisplayName.Length > 0 ? DisplayName : Name;
    public bool IsRunning => Status.Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
    public bool IsStopped => Status.Equals("STOPPED", StringComparison.OrdinalIgnoreCase);
    public bool IsAutomatic => StartType.StartsWith("AUTO", StringComparison.OrdinalIgnoreCase);
    public bool IsDisabled => StartType.Equals("DISABLED", StringComparison.OrdinalIgnoreCase);

    public string FriendlyStatus => Status.ToUpperInvariant() switch
    {
        "RUNNING" => "Running", "STOPPED" => "Stopped", "PAUSED" => "Paused",
        "START_PENDING" => "Starting", "STOP_PENDING" => "Stopping", "CONTINUE_PENDING" => "Resuming", "PAUSE_PENDING" => "Pausing",
        _ => Status.Length > 0 ? Status : "Unknown",
    };

    public string FriendlyStartType => StartType.ToUpperInvariant() switch
    {
        "AUTO_START" => "Automatic", "DEMAND_START" => "Manual", "DISABLED" => "Disabled",
        "BOOT_START" or "SYSTEM_START" => "Starts with Windows", _ => StartType.Length > 0 ? StartType : "Unknown",
    };

    public string FriendlyAccount => Account.ToUpperInvariant() switch
    {
        "LOCALSYSTEM" => "System", "NT AUTHORITY\\LOCALSERVICE" => "Local service", "NT AUTHORITY\\NETWORKSERVICE" => "Network service",
        _ => Account,
    };
}

/// <summary>Windows services via osquery <c>services</c> (kernel/file-system drivers excluded).</summary>
public sealed class ServicesModule(OsqueryRunner runner) : OsqueryAreaModuleBase(runner)
{
    public const string ModuleName = ModuleSlugs.Services;
    public const string Sql = "SELECT name, display_name, status, start_type, user_account, description FROM services WHERE service_type NOT LIKE '%DRIVER%';";
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Services;
    public override string DisplayName => "Services";
    protected override string FailedMessage => "Couldn't read the list of services on this PC.";

    /// <summary>Services from the last successful check, by service name (used by the row Start/Stop/Restart controls).</summary>
    public IReadOnlyDictionary<string, ServiceInfo> Latest { get; private set; } = new Dictionary<string, ServiceInfo>();

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking services…");
        var q = await QueryAsync(Sql, ct).ConfigureAwait(false);
        if (!q.Success) return AreaReport.Failed(FailedMessage);
        var list = q.Rows!.Select(ServiceInfo.FromRow).ToList();
        Latest = list.GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        return Build(list);
    }

    public static AreaReport Build(IReadOnlyList<ServiceInfo> all)
    {
        if (all.Count == 0) return new([], "No services were found on this PC.", DiagnosticStatus.Warning);
        string[] cols = ["Service", "Status", "Starts", "Runs as"];
        AreaRow Row(ServiceInfo s, AreaLevel l) => new(l, [s.Label, s.FriendlyStatus, s.FriendlyStartType, s.FriendlyAccount], Key: s.Name);
        var byName = all.OrderBy(s => s.Label, StringComparer.CurrentCultureIgnoreCase).ToList();

        var stoppedAuto = byName.Where(s => s.IsAutomatic && !s.IsRunning).ToList();
        var running = byName.Where(s => s.IsRunning).ToList();
        var disabled = byName.Where(s => s.IsDisabled).ToList();

        var cards = new List<AreaCard>
        {
            new("stopped", "Automatic services not running", stoppedAuto.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
                stoppedAuto.Count == 0 ? "All are running" : AreaModuleBase.Plural(stoppedAuto.Count, "service") + " stopped",
                string.Join(", ", stoppedAuto.Take(3).Select(s => s.Label)),
                cols, stoppedAuto.Select(s => Row(s, AreaLevel.Warning)).ToList(),
                EmptyText: null,
                Note: "These are set to start automatically. Some only run when needed or stop after finishing their work, so a few stopped ones are normal."),
            new("running", "Running services", AreaLevel.Ok, AreaModuleBase.Plural(running.Count, "service") + " running",
                $"Out of {all.Count} installed", cols, running.Select(s => Row(s, AreaLevel.Ok)).ToList()),
            new("disabled", "Disabled services", AreaLevel.Neutral, disabled.Count == 0 ? "None" : AreaModuleBase.Plural(disabled.Count, "service"),
                "Turned off and won't start", cols, disabled.Select(s => Row(s, AreaLevel.Neutral)).ToList()),
            new("all", "All services", AreaLevel.Neutral, AreaModuleBase.Plural(all.Count, "service"), "Every service on this PC",
                cols, byName.Select(s => Row(s, s.IsRunning ? AreaLevel.Ok : s.IsAutomatic ? AreaLevel.Warning : AreaLevel.Neutral)).ToList()),
        };
        var summary = $"{running.Count} running" + (stoppedAuto.Count > 0 ? $" · {AreaModuleBase.Plural(stoppedAuto.Count, "automatic service")} not running" : " · all automatic services running");
        // Stopped automatic services are common and usually harmless, so they don't turn the whole area amber.
        return new(cards, summary, DiagnosticStatus.Ok);
    }
}
