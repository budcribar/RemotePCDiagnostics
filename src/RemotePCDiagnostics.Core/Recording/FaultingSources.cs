using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// Wraps a PC's sources (usually a <see cref="RecordingReplay"/>'s) so each answer passes through a <see cref="FaultPlan"/> first: the
/// fault-injection UI tests break answers this way while the real pages run on them. With no rule in force every answer is the inner one.
/// </summary>
public sealed class FaultingSources(FaultPlan plan)
{
    public FaultPlan Plan => plan;

    public IWmiSource Wmi(IWmiSource inner) => new FaultingWmi(inner, plan);
    public IRegistrySource Registry(IRegistrySource inner) => new FaultingRegistry(inner, plan);
    public IPackageSource Packages(IPackageSource inner) => new FaultingPackages(inner, plan);
    public Security.IAntivirusProductSource Antivirus(Security.IAntivirusProductSource inner) => new FaultingAntivirus(inner, plan);
    public Core.Audio.IAudioStateSource Audio(Core.Audio.IAudioStateSource inner) => new FaultingAudio(inner, plan);
    public Core.Usb.IUsbTreeSource Usb(Core.Usb.IUsbTreeSource inner) => new FaultingUsb(inner, plan);
    public IProcessLauncher Launcher(IProcessLauncher inner) => new FaultingLauncher(inner, plan);
    public Alerts.IAlertReadings Alerts(Alerts.IAlertReadings inner) => new FaultingAlerts(inner, plan);

    /// <summary>A report file kept by name (<see cref="RecordingReplay.FileText"/>), through the plan.</summary>
    public async Task<string?> FileAsync(string name, Func<string?> read, CancellationToken ct)
    {
        if (plan.For(RecordedCall.FileKind, RecordingReplay.FileKey(name)) is not { } rule) return read();
        await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
        return FaultPlan.Apply(rule, read());
    }

    private sealed class FaultingWmi(IWmiSource inner, FaultPlan plan) : IWmiSource
    {
        public async Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.WmiKind, RecordingReplay.WmiKey(wmiNamespace, wql)) is not { } rule)
                return await inner.QueryAsync(wmiNamespace, wql, ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            return FaultPlan.Apply(rule, await inner.QueryAsync(wmiNamespace, wql, ct).ConfigureAwait(false), plan.ErrorFor(rule));
        }
    }

    private sealed class FaultingAlerts(Alerts.IAlertReadings inner, FaultPlan plan) : Alerts.IAlertReadings
    {
        public async Task<WmiQueryResult> ReadAsync(string reading, long afterRecordId, TimeSpan lookBack, CancellationToken ct)
        {
            if (plan.For(RecordedCall.AlertsKind, RecordingReplay.AlertsKey(reading)) is not { } rule)
                return await inner.ReadAsync(reading, afterRecordId, lookBack, ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            return FaultPlan.Apply(rule, await inner.ReadAsync(reading, afterRecordId, lookBack, ct).ConfigureAwait(false), plan.ErrorFor(rule));
        }
    }

    private sealed class FaultingRegistry(IRegistrySource inner, FaultPlan plan) : IRegistrySource
    {
        public async Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.RegistryKind, RecordingReplay.RegistryKey(read.Location, read.Describe())) is not { } rule)
                return await inner.ReadAsync(read, ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            return FaultPlan.Apply(rule, await inner.ReadAsync(read, ct).ConfigureAwait(false), plan.ErrorFor(rule));
        }
    }

    private sealed class FaultingPackages(IPackageSource inner, FaultPlan plan) : IPackageSource
    {
        public async Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.PackagesKind, RecordingReplay.PackagesKey) is not { } rule)
                return await inner.ReadPackagesAsync(ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            return FaultPlan.Apply(rule, await inner.ReadPackagesAsync(ct).ConfigureAwait(false), plan.ErrorFor(rule));
        }
    }

    private sealed class FaultingAntivirus(Security.IAntivirusProductSource inner, FaultPlan plan) : Security.IAntivirusProductSource
    {
        public async Task<Security.AntivirusInventoryResult> ReadAsync(CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.AntivirusKind, RecordingReplay.AntivirusKey) is not { } rule)
                return await inner.ReadAsync(ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            var answer = await inner.ReadAsync(ct).ConfigureAwait(false);
            if (plan.ErrorFor(rule) is { } error) return Security.AntivirusInventoryResult.Unavailable(error);
            return rule.Fault == Faults.Empty ? answer with { Products = [] } : answer;
        }
    }

    private sealed class FaultingAudio(Core.Audio.IAudioStateSource inner, FaultPlan plan) : Core.Audio.IAudioStateSource
    {
        public async Task<Core.Audio.AudioState> ReadAsync(CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.AudioKind, RecordingReplay.AudioKey) is not { } rule)
                return await inner.ReadAsync(ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            var answer = await inner.ReadAsync(ct).ConfigureAwait(false);
            if (plan.ErrorFor(rule) is { } error) return Core.Audio.AudioState.Unavailable(error);
            return rule.Fault switch
            {
                Faults.Empty => answer with { Endpoints = [], Sessions = [] },
                Faults.Garbage => Core.Audio.AudioState.FromJson(Faults.GarbageText),
                _ => answer,
            };
        }
    }

    private sealed class FaultingUsb(Core.Usb.IUsbTreeSource inner, FaultPlan plan) : Core.Usb.IUsbTreeSource
    {
        public async Task<Core.Usb.UsbSnapshot> ReadAsync(CancellationToken ct = default)
        {
            if (plan.For(RecordedCall.UsbKind, RecordingReplay.UsbKey) is not { } rule)
                return await inner.ReadAsync(ct).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, ct).ConfigureAwait(false);
            var answer = await inner.ReadAsync(ct).ConfigureAwait(false);
            if (plan.ErrorFor(rule) is { } error) return Core.Usb.UsbSnapshot.Unavailable(error);
            return rule.Fault switch
            {
                Faults.Empty => answer with { Nodes = [] },
                Faults.Garbage => Core.Usb.UsbSnapshot.FromJson(Faults.GarbageText),
                _ => answer,
            };
        }
    }

    private sealed class FaultingLauncher(IProcessLauncher inner, FaultPlan plan) : IProcessLauncher
    {
        public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (plan.For(RecordedCall.ProcessKind, RecordingReplay.ProcessKey(fileName, arguments)) is not { } rule)
                return await inner.RunAsync(fileName, arguments, timeout, cancellationToken).ConfigureAwait(false);
            await FaultPlan.WaitAsync(rule, cancellationToken).ConfigureAwait(false);
            return FaultPlan.Apply(rule, await inner.RunAsync(fileName, arguments, timeout, cancellationToken).ConfigureAwait(false));
        }
    }
}
