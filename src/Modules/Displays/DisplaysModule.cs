using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Display;

namespace RemotePCDiagnostics.Modules.Displays;

/// <summary>
/// Displays &amp; video outputs: every monitor Windows sees with its maker, model, serial and size from the EDID, the connector it's on
/// (built-in, HDMI, DisplayPort, USB-C, VGA, DVI, a USB display adapter), its current, native and largest mode and refresh rate, scaling,
/// HDR and which graphics adapter drives it, which one is primary; a missing or damaged EDID, a monitor running below its native resolution
/// or refresh rate, and one connected but not in use; every video output of each graphics adapter and what's on it; display driver resets
/// in the System log tied to the adapter and its displays; and video outputs turned off in the BIOS (HP, Lenovo, Dell; read through the
/// Agent). The display configuration is read in the app (<see cref="IDisplaySource"/>), which needs no administrator rights, so the check
/// also answers on a PC no one is looking at. Nothing is changed.
/// </summary>
public sealed class DisplaysModule(IDisplaySource displays, SystemCommandRunner commands, IWmiSource wmi, IRegistrySource registry,
    IHostQueries? host = null, ILogger? log = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.Displays;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Displays;
    public override string DisplayName => "Displays & video outputs";
    protected override string FailedMessage => "Couldn't check the displays on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 3, "Reading monitors and video outputs…");
        var snapshot = await displays.ReadAsync(ct).ConfigureAwait(false);
        if (snapshot.Error is { } err) LogWarn($"{Name}: display configuration unreadable: {err}");
        else Log($"{Name}: {snapshot.Outputs.Count} outputs, {snapshot.Monitors.Count} monitors");

        progress.ReportStep(2, 3, "Reading display driver resets in the System log…");
        var events = await new WindowsEventLog(commands, host, ModuleName)
            .QueryAsync("System", GraphicsDriverCrashes.SystemQuery, GraphicsDriverCrashes.MaxEvents, ct).ConfigureAwait(false);

        progress.ReportStep(3, 3, "Checking for video outputs turned off in the BIOS…");
        DisplayFirmwareReading? firmware;
        try { firmware = await DisplayFirmwarePorts.ReadAsync(wmi, registry, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: BIOS settings unreadable: {ex.Message}");
            firmware = new(null, [], "The BIOS settings couldn't be read: " + ex.Message);
        }
        return DisplayAnalysis.Build(snapshot, events, firmware);
    }
}
