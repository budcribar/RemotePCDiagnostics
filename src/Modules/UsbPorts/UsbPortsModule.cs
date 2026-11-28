using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Usb;

namespace RemotePCDiagnostics.Modules.UsbPorts;

/// <summary>
/// USB ports &amp; devices: every USB controller, hub and device from the Windows device tree with its port and negotiated speed, devices
/// with a problem code, USB 3 devices running at USB 2 speed, hub ports that failed (over-current, failed enumeration), hub and controller
/// errors in the System log, devices grouped by the dock or hub they sit behind, several of them dropping at once during the run, and
/// ports turned off in the BIOS (HP, Lenovo, Dell; read through the Agent). The tree is read in the app (<see cref="IUsbTreeSource"/>), which
/// needs no administrator rights. Nothing is changed; the Restart and Enable buttons are Device Manager's.
/// </summary>
public sealed class UsbPortsModule(IUsbTreeSource usb, SystemCommandRunner commands, IWmiSource wmi, IRegistrySource registry,
    IHostQueries? host = null, ILogger? log = null, TimeSpan? dropWatch = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.UsbPorts;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.UsbPorts;
    public override string DisplayName => "USB ports & devices";
    protected override string FailedMessage => "Couldn't check the USB ports and devices on this PC.";

    /// <summary>How long the check waits before reading the tree again, to catch devices dropping together while it runs.</summary>
    private readonly TimeSpan _dropWatch = dropWatch ?? TimeSpan.FromSeconds(2);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 4, "Reading USB controllers, hubs and devices…");
        var first = await usb.ReadAsync(ct).ConfigureAwait(false);
        if (first.Error is { } err) LogWarn($"{Name}: USB tree unreadable: {err}");

        progress.ReportStep(2, 4, "Reading USB errors in the System log…");
        var events = await new WindowsEventLog(commands, host, ModuleName).QueryAsync("System", UsbAnalysis.EventQuery(), 300, ct).ConfigureAwait(false);

        progress.ReportStep(3, 4, "Checking for USB ports turned off in the BIOS…");
        UsbFirmwareReading? firmware;
        try { firmware = await UsbFirmwarePorts.ReadAsync(wmi, registry, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: BIOS settings unreadable: {ex.Message}");
            firmware = new(null, [], "The BIOS settings couldn't be read: " + ex.Message);
        }

        progress.ReportStep(4, 4, "Watching for devices dropping…");
        var tree = first;
        IReadOnlyList<UsbDrop> drops = [];
        if (first.Error is null && !commands.IsScripted && _dropWatch > TimeSpan.Zero)
        {
            await Task.Delay(_dropWatch, ct).ConfigureAwait(false);
            var again = await usb.ReadAsync(ct).ConfigureAwait(false);
            drops = UsbAnalysis.Drops(first, again, DateTimeOffset.Now);
            if (again.Error is null) tree = again;
        }
        return UsbAnalysis.Build(tree, events, firmware, drops);
    }
}
