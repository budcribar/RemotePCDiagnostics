using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Base for areas backed by the bundled osqueryi: unavailable (friendly text) when the tool is missing.</summary>
public abstract class OsqueryAreaModuleBase(OsqueryRunner runner) : AreaModuleBase(runner.Options.Log.AsAction())
{
    public const string ToolMissingMessage = "The diagnostics tool wasn't found. Please reinstall the app.";
    protected OsqueryRunner Runner => runner;

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        var a = runner.CheckAvailability();
        if (a.IsAvailable) return Task.FromResult(a);
        Log($"{Name}: {a.Reason}");
        return Task.FromResult(ModuleAvailability.Unavailable(ToolMissingMessage));
    }

    protected Task<OsqueryQueryResult> QueryAsync(string sql, CancellationToken ct) => runner.RunQueryAsync(sql, ct);
}
