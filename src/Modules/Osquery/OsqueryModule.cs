namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Hardware inventory via osqueryi (system_info, cpu_info, memory_devices, disk_info).</summary>
public sealed class OsqueryModule(OsqueryRunner runner) : IDiagnosticModule
{
    public const string ToolMissingMessage = "The hardware tool wasn't found. Please reinstall the app.";
    public const string AllFailedMessage = "Couldn't read hardware details on this PC.";

    public const string ModuleName = ModuleSlugs.Osquery;
    public string Name => ModuleName;
    public Guid Id => ModuleIds.Osquery;
    public string DisplayName => "Hardware inventory";
    public event EventHandler<DiagnosticResult>? Updated;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        var a = runner.CheckAvailability();
        if (a.IsAvailable) return Task.FromResult(a);
        runner.Options.Log.Line(a.Reason ?? runner.NotFoundMessage); // developer detail (path) goes to the log only
        return Task.FromResult(ModuleAvailability.Unavailable(ToolMissingMessage));
    }

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        var inv = await HardwareInventory.CollectAsync(runner, progress, cancellationToken).ConfigureAwait(false);
        var status = inv.FailedSections switch { 0 => DiagnosticStatus.Ok, 4 => DiagnosticStatus.Error, _ => DiagnosticStatus.Warning };
        return new DiagnosticResult<HardwareInventory>(Name, status, Summarize(inv), DateTimeOffset.Now, inv);
    }

    /// <summary>End-user status text (no query names, exit codes or paths).</summary>
    internal static string Summarize(HardwareInventory inv)
    {
        if (inv.FailedSections == 4) return inv.ToolMissing ? ToolMissingMessage : AllFailedMessage;
        return inv.FriendlySummary();
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
