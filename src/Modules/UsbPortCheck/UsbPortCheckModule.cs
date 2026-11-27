using RemotePCDiagnostics.Core.Usb;
using Check = RemotePCDiagnostics.Core.Usb.UsbPortCheck;

namespace RemotePCDiagnostics.Modules.UsbPortCheck;

/// <summary>
/// The interactive USB port check (Interactive tests page): watches the USB tree while the person plugs a USB stick or mouse into each
/// port in turn, shows each arrival live with its port and speed, and notes several devices behind one dock dropping at once. Finish stops
/// watching; the person then answers "Did every device work?". Nothing is changed on the PC.
/// </summary>
public sealed class UsbPortCheckModule(IUsbTreeSource usb, ILogger? log = null, TimeSpan? poll = null, TimeSpan? maxWatch = null) : OnDemandModuleBase(log), IUsbPortCheckModule
{
    private readonly TimeSpan _poll = poll ?? Check.PollInterval;
    private readonly TimeSpan _max = maxWatch ?? Check.MaxWatch;
    private TaskCompletionSource? _finish;
    private UsbPortCheckReport _live = UsbPortCheckReport.Empty;

    public override string Name => ModuleSlugs.UsbPortCheck;
    public override Guid Id => ModuleIds.UsbPortCheck;
    public override string DisplayName => "USB port check";

    /// <summary>What the check has seen so far in this watch (the page follows it while the run is going).</summary>
    public UsbPortCheckReport Live { get { lock (Gate) return _live; } }

    /// <summary>Raised when a device arrives or drops while watching.</summary>
    public event EventHandler? Changed;

    /// <summary>Stops watching; the run ends and asks the person whether every device worked.</summary>
    public void Finish() { lock (Gate) _finish?.TrySetResult(); }

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (Gate) { _finish = finish; _live = UsbPortCheckReport.Empty with { Watching = true }; }
        try
        {
            var before = await usb.ReadAsync(ct).ConfigureAwait(false);
            if (before.Error is { } err)
                return new DiagnosticResult(Name, DiagnosticStatus.Error, "The USB devices couldn't be read, so the port check can't follow them: " + err, DateTimeOffset.Now);
            progress?.Report(Check.WaitingMessage);
            Log($"{Name}: watching {before.Nodes.Count} USB nodes");
            var until = DateTimeOffset.UtcNow + _max;
            var arrivals = new List<UsbArrival>();
            var drops = new List<UsbDrop>();
            while (!finish.Task.IsCompleted && DateTimeOffset.UtcNow < until)
            {
                await Task.WhenAny(finish.Task, Task.Delay(_poll, ct)).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (finish.Task.IsCompleted) break;
                var now = await usb.ReadAsync(ct).ConfigureAwait(false);
                if (now.Error is not null) continue;
                var at = DateTimeOffset.Now;
                var came = Check.Arrivals(before, now, at);
                var went = UsbAnalysis.Drops(before, now, at);
                before = now;
                if (came.Count == 0 && went.Count == 0) continue;
                arrivals.AddRange(came);
                drops.AddRange(went);
                foreach (var a in came) Log($"{Name}: {a.Name} on {a.Where} at {a.Speed}");
                foreach (var d in went) LogWarn($"{Name}: {d.Devices.Count} devices dropped together behind {d.HubName}");
                var live = new UsbPortCheckReport([.. arrivals], [.. drops], null, true);
                lock (Gate) _live = live;
                progress?.Report(Check.Outcome(live).Message);
                try { Changed?.Invoke(this, EventArgs.Empty); } catch (Exception ex) { LogWarn($"{Name}: page update failed: {ex.Message}"); }
            }
            var done = new UsbPortCheckReport([.. arrivals], [.. drops], null, false,
                finish.Task.IsCompleted ? null : $"Stopped watching after {(int)_max.TotalMinutes} minutes.");
            lock (Gate) _live = done;
            return Check.ToResult(done);
        }
        finally
        {
            lock (Gate) { _finish = null; if (_live.Watching) _live = _live with { Watching = false }; }
        }
    }
}
