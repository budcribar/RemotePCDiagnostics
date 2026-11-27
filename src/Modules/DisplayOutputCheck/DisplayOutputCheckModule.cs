using RemotePCDiagnostics.Core.Display;
using Check = RemotePCDiagnostics.Core.Display.DisplayOutputCheck;

namespace RemotePCDiagnostics.Modules.DisplayOutputCheck;

/// <summary>
/// The interactive video output check (Interactive tests page): watches the display configuration while the person plugs a monitor into
/// each video port in turn, shows each arrival live with its connector, mode and EDID state, and asks "Did the picture appear?" for each.
/// A port where nothing shows up at all can be reported too. A monitor that drops and comes back more than once is flagged (a loose cable).
/// Finish stops watching. Nothing is changed on the PC: Windows itself extends the desktop onto a new monitor.
/// </summary>
public sealed class DisplayOutputCheckModule(IDisplaySource displays, ILogger? log = null, TimeSpan? poll = null, TimeSpan? maxWatch = null)
    : OnDemandModuleBase(log), IDisplayOutputCheckModule
{
    private readonly TimeSpan _poll = poll ?? Check.PollInterval;
    private readonly TimeSpan _max = maxWatch ?? Check.MaxWatch;
    private TaskCompletionSource? _finish;
    private DisplayOutputCheckReport _live = DisplayOutputCheckReport.Empty;

    public override string Name => ModuleSlugs.DisplayOutputCheck;
    public override Guid Id => ModuleIds.DisplayOutputCheck;
    public override string DisplayName => "Video output check";

    public DisplayOutputCheckReport Live { get { lock (Gate) return _live; } }

    public event EventHandler? Changed;

    public void Finish() { lock (Gate) _finish?.TrySetResult(); }

    public void Answer(string key, bool pictureAppeared)
    {
        lock (Gate)
        {
            if (!_live.Watching) return;
            _live = Check.WithAnswer(_live, key, pictureAppeared);
        }
        Raise();
    }

    public void ReportNoSignal(string port)
    {
        lock (Gate)
        {
            if (!_live.Watching) return;
            _live = Check.WithNoSignal(_live, port, DateTimeOffset.Now);
        }
        LogWarn($"{Name}: the person reported no picture and no monitor on {port}");
        Raise();
    }

    private void Raise()
    {
        try { Changed?.Invoke(this, EventArgs.Empty); } catch (Exception ex) { LogWarn($"{Name}: page update failed: {ex.Message}"); }
    }

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (Gate) { _finish = finish; _live = DisplayOutputCheckReport.Empty with { Watching = true }; }
        try
        {
            var before = await displays.ReadAsync(ct).ConfigureAwait(false);
            if (before.Error is { } err)
                return new DiagnosticResult(Name, DiagnosticStatus.Error, "The displays couldn't be read, so the output check can't follow them: " + err, DateTimeOffset.Now);
            progress?.Report(Check.WaitingMessage);
            Log($"{Name}: watching {before.Outputs.Count} outputs, {before.Monitors.Count} monitors");
            var until = DateTimeOffset.UtcNow + _max;
            while (!finish.Task.IsCompleted && DateTimeOffset.UtcNow < until)
            {
                await Task.WhenAny(finish.Task, Task.Delay(_poll, ct)).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                var now = await displays.ReadAsync(ct).ConfigureAwait(false);
                if (now.Error is not null) continue;
                DisplayOutputCheckReport live;
                lock (Gate)
                {
                    var next = Check.Next(_live.Arrivals, before, now, DateTimeOffset.Now);
                    if (next.SequenceEqual(_live.Arrivals)) { before = now; continue; }
                    foreach (var a in next.Where(a => _live.Arrivals.All(x => x.Key != a.Key)))
                        Log($"{Name}: {a.Monitor} on {a.Connector} ({a.Adapter}) {(a.Active ? a.Mode : "not active")}");
                    _live = live = _live with { Arrivals = next };
                }
                before = now;
                progress?.Report(Check.Outcome(live).Message);
                Raise();
            }
            DisplayOutputCheckReport done;
            lock (Gate)
                _live = done = _live with { Watching = false, Notice = finish.Task.IsCompleted ? null : $"Stopped watching after {(int)_max.TotalMinutes} minutes." };
            return Check.ToResult(done);
        }
        finally
        {
            lock (Gate) { _finish = null; if (_live.Watching) _live = _live with { Watching = false }; }
        }
    }
}
