using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Hardware inventory (computer, processor, memory, drives, graphics, network adapters, BIOS), read from <paramref name="source"/>:
/// WMI through the Agent in the app, osquery in the Store edition without an Agent. The check keeps its old id and name.</summary>
public sealed class OsqueryModule(IHardwareInventorySource source) : IDiagnosticModule
{
    public const string ToolMissingMessage = "The hardware tool wasn't found. Please reinstall the app.";
    public const string AllFailedMessage = "Couldn't read hardware details on this PC.";

    public const string ModuleName = ModuleSlugs.Osquery;
    public string Name => ModuleName;
    public Guid Id => ModuleIds.Osquery;
    public string DisplayName => "Hardware inventory";
    public event EventHandler<DiagnosticResult>? Updated;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => source.CheckAvailabilityAsync(cancellationToken);

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        var inv = await source.ReadAsync(progress, cancellationToken).ConfigureAwait(false);
        var status = inv.AllSectionsFailed ? DiagnosticStatus.Error : inv.FailedSections == 0 ? DiagnosticStatus.Ok : DiagnosticStatus.Warning;
        return new DiagnosticResult<HardwareInventory>(Name, status, Summarize(inv), DateTimeOffset.Now, inv);
    }

    /// <summary>End-user status text (no query names, exit codes or paths).</summary>
    internal static string Summarize(HardwareInventory inv)
    {
        if (inv.AllSectionsFailed) return inv.ToolMissing ? ToolMissingMessage : AllFailedMessage;
        return inv.FriendlySummary();
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
