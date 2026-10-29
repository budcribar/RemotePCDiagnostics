namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Hardware inventory via osqueryi (system_info, cpu_info, memory_devices, disk_info).</summary>
public sealed class OsqueryModule(OsqueryRunner runner) : IDiagnosticModule
{
    public string Name => "Osquery";
    public event EventHandler<DiagnosticResult>? Updated;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(runner.CheckAvailability());

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        var inv = await HardwareInventory.CollectAsync(runner, progress, cancellationToken).ConfigureAwait(false);
        var status = inv.FailedSections switch { 0 => DiagnosticStatus.Ok, 4 => DiagnosticStatus.Error, _ => DiagnosticStatus.Warning };
        return new DiagnosticResult<HardwareInventory>(Name, status, Summarize(inv), DateTimeOffset.Now, inv);
    }

    internal static string Summarize(HardwareInventory inv)
    {
        if (inv.FailedSections == 4) return "All osquery queries failed: " + inv.System.Error;
        var parts = new List<string>();
        var sys = inv.System.Items.FirstOrDefault();
        if (sys is not null)
        {
            var model = $"{sys.HardwareVendor} {sys.HardwareModel}".Trim();
            if (model.Length > 0) parts.Add(model);
            if (sys.PhysicalMemoryBytes > 0) parts.Add(HardwareInventory.FormatBytes(sys.PhysicalMemoryBytes) + " RAM");
        }
        if (inv.Disks.Success) parts.Add($"{inv.Disks.Items.Count} disk(s)");
        var text = parts.Count > 0 ? string.Join(" · ", parts) : "Inventory collected";
        return inv.FailedSections > 0 ? $"{text} ({inv.FailedSections} query(ies) failed)" : text;
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
