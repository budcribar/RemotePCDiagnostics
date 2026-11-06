using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>Registers modules and runs them independently, recording results in the store.</summary>
public sealed class DiagnosticsService
{
    /// <summary>Optional logger (the Host passes one from App.Loggers).</summary>
    public ILogger? Log { get; set; }
    private int _suiteRunning;
    private readonly ConcurrentDictionary<string, (DateTimeOffset Stamp, string Label)> _suiteLabels = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _suiteCts;

    /// <summary>True while a stress suite is running (both dashboard run buttons are disabled).</summary>
    public bool IsStressSuiteRunning => Volatile.Read(ref _suiteRunning) == 1;
    /// <summary>True while a stress suite or any individual stress test module is running.</summary>
    public bool IsAnyStressRunning => IsStressSuiteRunning || StressOrder.Any(IsRunning);

    /// <summary>The stress suite's run order (module slugs): the registered stress tests sorted on DependsOn and RunAfter, ties by group
    /// and Order. Built-ins chain CPU, Memory, Disk, GPU, Network through RunAfter; a plugin stress test joins by its own RunAfter.</summary>
    public IReadOnlyList<string> StressOrder => ModuleOrdering.Sort(_modules.OfType<IStressSuiteModule>()
        .Select(m => Catalog.Get(m.Id)).OfType<ModuleDescriptor>().Where(d => d.Kind == ModuleKind.StressTest && IsRunnable(d.Id))).Select(d => d.Slug).ToList();
    /// <summary>Latest suite progress, so a page opened mid-run can show it.</summary>
    public StressSuiteProgress? LastStressSuiteProgress { get; private set; }
    /// <summary>Raised on every suite progress change.</summary>
    public event EventHandler<StressSuiteProgress>? StressSuiteProgressChanged;

    /// <summary>"short run"/"extended run" when the module's current result came from the stress suite; otherwise null.</summary>
    public string? StressRunLabel(string moduleName) =>
        _suiteLabels.TryGetValue(moduleName, out var l) && _store.Get(moduleName).Timestamp == l.Stamp ? l.Label : null;

    /// <summary>"short run"/"extended run" while a stress suite is running; otherwise null (for result logging).</summary>
    public string? CurrentSuiteLabel { get; private set; }

    /// <summary>Watchdog: how long past its set duration a stress test may run before the suite asks it to stop. Must exceed the longest
    /// self-timeout inside a test (the memory test kills its helper after 60 s).</summary>
    public TimeSpan StressHangGrace { get; set; } = TimeSpan.FromSeconds(90);
    /// <summary>Watchdog: how long a test gets to return after being asked to stop before the suite gives up on it and moves on.</summary>
    public TimeSpan StressStopGrace { get; set; } = TimeSpan.FromSeconds(15);
    /// <summary>Tests only: replaces duration + <see cref="StressHangGrace"/> as the first limit.</summary>
    public TimeSpan? StressHangLimitOverride { get; set; }

    /// <summary>How long a stress test's cleanup gets before the runner logs a warning and moves on.</summary>
    public TimeSpan StressCleanupGrace { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Calls the test's cleanup on its own thread, so a cleanup that blocks can't stall the runner. Always called after a stress test
    /// ends, however it ended (finished, stopped, failed, timed out and abandoned). Never throws.</summary>
    private async Task CleanupStressAsync(IStressSuiteModule m)
    {
        try
        {
            var task = Task.Factory.StartNew(() => m.CleanupAsync(), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();
            using var d = new CancellationTokenSource();
            var first = await Task.WhenAny(task, Task.Delay(StressCleanupGrace, d.Token)).ConfigureAwait(false);
            d.Cancel();
            if (first != task)
            {
                Log.Info($"Stress suite: cleanup for {m.Name} did not finish within {StressCleanupGrace.TotalSeconds:0}s; moving on");
                _ = task.ContinueWith(t => { _ = t.Exception; }, TaskScheduler.Default);
                return;
            }
            await task.ConfigureAwait(false);
        }
        catch (Exception ex) { Log.Warn($"Stress suite: cleanup for {m.Name} failed: {ex.Message}"); }
    }

    /// <summary>Runs one stress test with a hang watchdog. Result is null when the test never returned (the message says why).
    /// A test that hangs keeps running in the background, since a stuck thread can't be killed safely.</summary>
    private async Task<(DiagnosticResult? Result, string Message)> RunWithWatchdogAsync(IStressSuiteModule m, CancellationToken suiteCt)
    {
        try { return await RunWatchedAsync(m, suiteCt).ConfigureAwait(false); }
        finally { await CleanupStressAsync(m).ConfigureAwait(false); }
    }

    private async Task<(DiagnosticResult? Result, string Message)> RunWatchedAsync(IStressSuiteModule m, CancellationToken suiteCt)
    {
        var run = RunAsync(m, null, suiteCt);
        var limit = StressHangLimitOverride ?? (m.Duration + StressHangGrace);
        using (var d1 = CancellationTokenSource.CreateLinkedTokenSource(suiteCt))
        {
            var first = await Task.WhenAny(run, Task.Delay(limit, d1.Token)).ConfigureAwait(false);
            d1.Cancel();
            if (first == run) return (await run.ConfigureAwait(false), "");
        }
        if (!suiteCt.IsCancellationRequested)
        {
            Log.Warn($"Stress suite: {m.Name} ran past its time limit ({limit.TotalSeconds:0}s); asking it to stop");
            try { m.Stop(); } catch { }
        }
        using var d2 = new CancellationTokenSource();
        var second = await Task.WhenAny(run, Task.Delay(StressStopGrace, d2.Token)).ConfigureAwait(false);
        d2.Cancel();
        if (second == run) return (await run.ConfigureAwait(false), "");
        var reason = suiteCt.IsCancellationRequested
            ? "Stopped, but the test did not respond and is still running in the background"
            : "The test stopped responding and was skipped; it may still be running in the background";
        _store.Set(new DiagnosticResult(m.Name, DiagnosticStatus.Error, reason, DateTimeOffset.Now));
        return (null, reason);
    }

    /// <summary>Cancels a running stress suite (stops the current test and ends the sequence).</summary>
    public void CancelStressSuite()
    {
        lock (_gate) { try { _suiteCts?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    private readonly List<IDiagnosticModule> _modules = new();
    private readonly ResultStore _store;
    private readonly ConcurrentDictionary<string, Task<DiagnosticResult>> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CheckProgress> _progress = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>Current sub-step progress of a running module, or null when not running or no progress reported yet.</summary>
    public CheckProgress? GetProgress(string moduleName) => _progress.TryGetValue(moduleName, out var p) ? p : null;

    /// <summary>Raised when a running module reports sub-step progress (or finishes, with null).</summary>
    public event EventHandler<(string ModuleName, CheckProgress? Progress)>? ProgressChanged;

    /// <summary>Every known module, including ones that can't run on this PC (hardware missing, retired). History and the export name
    /// results through it; <see cref="Modules"/> stays the list of runnable modules.</summary>
    public ModuleCatalog Catalog { get; }

    public DiagnosticsService(ResultStore store, IEnumerable<IDiagnosticModule>? modules = null, ModuleCatalog? catalog = null)
    {
        _store = store;
        Catalog = catalog ?? new ModuleCatalog();
        foreach (var m in modules ?? []) Register(m);
        RejectDependencyCycles();
        StartHardwareDetection();
    }

    /// <summary>
    /// Every module in a DependsOn / RunAfter loop is marked not executable (Disabled in the catalog, so History still names it) and the
    /// loop is logged. Runs at construction and again after plugin descriptors are applied to the catalog. Returns the loops found.
    /// </summary>
    public IReadOnlyList<IReadOnlyList<Guid>> RejectDependencyCycles()
    {
        var registered = _modules.Select(m => Catalog.Get(m.Id)).OfType<ModuleDescriptor>().ToList();
        var cycles = ModuleOrdering.FindCycles(registered);
        foreach (var cycle in cycles)
        {
            foreach (var id in cycle) Catalog.Disable(id);
            try { Log.Info($"Modules: dependency loop, not run: {string.Join(" -> ", cycle.Select(Catalog.DisplayName))}"); } catch { }
        }
        if (cycles.Count > 0) Volatile.Write(ref _visible, null);
        return cycles;
    }

    private bool IsRunnable(Guid id) => Catalog.StateOf(id) != ModuleState.Disabled;

    private IReadOnlyList<IDiagnosticModule>? _visible;

    /// <summary>Registered modules, minus hardware-gated ones whose hardware wasn't found (see <see cref="IHardwareGatedModule"/>).</summary>
    public IReadOnlyList<IDiagnosticModule> Modules
    {
        get
        {
            var v = Volatile.Read(ref _visible);
            if (v is null) { v = _modules.Where(m => IsVisible(m) && IsRunnable(m.Id)).ToArray(); Volatile.Write(ref _visible, v); }
            return v;
        }
    }

    /// <summary><see cref="Modules"/> plus detectable modules whose detection hasn't finished yet: a run started right at startup still
    /// includes them (the run waits for detection), while pages only list them once they are known to apply.</summary>
    private IEnumerable<IDiagnosticModule> Runnable =>
        _modules.Where(m => IsRunnable(m.Id) && (m is IDetectableModule and not IHardwareGatedModule
            ? !_detections.TryGetValue(m.Id, out var d) || d.Applies // one read: detection may finish meanwhile
            : IsVisible(m)));

    /// <summary>True when <see cref="RunAsync(string, IProgress{string}?, CancellationToken)"/> would accept the module: unlike
    /// <see cref="Modules"/> this includes a detectable module whose detection hasn't finished yet (the run waits for it).</summary>
    public bool CanRun(string moduleName) => FindRunnable(moduleName) is not null;

    private IDiagnosticModule? FindRunnable(string moduleName) =>
        Runnable.FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));

    private bool IsVisible(IDiagnosticModule m) => m switch
    {
        IHardwareGatedModule g => g.IsPresent,
        IDetectableModule => _detections.TryGetValue(m.Id, out var d) && d.Applies,
        _ => true,
    };

    private readonly ConcurrentDictionary<Guid, ModuleDetection> _detections = new();

    /// <summary>What the module's last DetectAsync said, or null before detection finished (and for modules that don't detect).</summary>
    public ModuleDetection? DetectionOf(Guid moduleId) => _detections.GetValueOrDefault(moduleId);

    /// <summary>The instances a per-device module runs against (those the test applies to).</summary>
    public IReadOnlyList<ModuleInstance> InstancesOf(IDiagnosticModule module) =>
        _detections.TryGetValue(module.Id, out var d) ? d.Instances.Where(i => i.Applies).ToList() : [];

    /// <summary>Runs DetectAsync again for every detectable module (the host calls it on device arrival and removal).</summary>
    public Task RedetectAsync() => Task.WhenAll(_modules.OfType<IDetectableModule>().Select(DetectAsync));

    private async Task DetectAsync(IDetectableModule m)
    {
        Interlocked.Increment(ref _detecting);
        ModuleDetection detection;
        try { detection = await m.DetectAsync().ConfigureAwait(false); }
        catch (Exception ex) { detection = ModuleDetection.NotApplicable($"Detection failed: {ex.Message}"); }
        finally { Interlocked.Decrement(ref _detecting); }
        _detections[m.Id] = detection;
        Catalog.SetApplies(m.Id, detection.Applies);
        Volatile.Write(ref _visible, null);
        try { ModulesChanged?.Invoke(this, EventArgs.Empty); } catch { }
        _store.Touch(m.Name); // store-aware pages re-render
        try { Log.Info(detection.Applies ? $"{m.Name}: {detection.Instances.Count(i => i.Applies)} instance(s)" : $"{m.Name}: doesn't apply ({detection.NotApplicableReason})"); } catch { }
    }

    /// <summary>True while hardware detection for a gated module is still running (pages show "looking…" instead of "not found").</summary>
    public bool IsDetectingHardware => Volatile.Read(ref _detecting) > 0;
    private int _detecting;

    /// <summary>Raised when the visible module list changes (a gated module's hardware was found).</summary>
    public event EventHandler? ModulesChanged;

    /// <summary>Runs each gated module's detection once in the background; never blocks the caller, never throws.</summary>
    private void StartHardwareDetection()
    {
        foreach (var d in _modules.OfType<IDetectableModule>()) _ = Task.Run(() => DetectAsync(d));
        foreach (var g in _modules.OfType<IHardwareGatedModule>())
        {
            Interlocked.Increment(ref _detecting);
            _ = Task.Run(async () =>
            {
                var found = false;
                try { found = await g.DetectPresenceAsync().ConfigureAwait(false); }
                catch (Exception ex) { try { Log.Warn($"{g.Name}: detection failed, hidden: {ex.Message}"); } catch { } }
                finally { Interlocked.Decrement(ref _detecting); }
                Volatile.Write(ref _visible, null);
                Catalog.RaiseChanged();
                try { ModulesChanged?.Invoke(this, EventArgs.Empty); } catch { }
                _store.Set(DiagnosticResult.NotRun(g.Name)); // nudges store-aware pages to re-render
                if (found) try { Log.Info($"{g.Name}: hardware found, shown"); } catch { }
            });
        }
    }

    public void Register(IDiagnosticModule module)
    {
        if (_modules.Any(m => string.Equals(m.Name, module.Name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Module '{module.Name}' already registered.");
        if (module.Id == Guid.Empty)
            throw new InvalidOperationException($"Module '{module.Name}' has no Id.");
        if (_modules.FirstOrDefault(m => m.Id == module.Id) is { } clash)
            throw new InvalidOperationException($"Module '{module.Name}' has the same Id ({module.Id}) as '{clash.Name}'.");
        Catalog.Add(module);
        _modules.Add(module);
        Volatile.Write(ref _visible, null);
        module.Updated += (_, r) => _store.Set(MarkStopped(module, r));
        _store.Set(DiagnosticResult.NotRun(module.Name));
    }

    /// <summary>Stress tests know from their own report (not the message) when the user stopped them: flag it as cancelled.</summary>
    private static DiagnosticResult MarkStopped(IDiagnosticModule module, DiagnosticResult r) =>
        !r.Cancelled && module is IStressSuiteModule stress && stress.IsStoppedByUserResult(r) ? r with { Cancelled = true } : r;

    public async Task<DiagnosticResult> RunAsync(string moduleName, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var module = FindRunnable(moduleName) ?? throw new ArgumentException($"Unknown module '{moduleName}'.", nameof(moduleName));
        return await RunAsync(module, progress, ct).ConfigureAwait(false);
    }

    /// <summary>Runs one device of a per-device module (a webcam picked on its page). The module's result then counts this device's new
    /// result and the latest result of each other device.</summary>
    public async Task<DiagnosticResult> RunInstanceAsync(string moduleName, string instanceKey, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var module = FindRunnable(moduleName) ?? throw new ArgumentException($"Unknown module '{moduleName}'.", nameof(moduleName));
        if (module is not IPerDeviceModule) throw new ArgumentException($"'{moduleName}' doesn't run per device.", nameof(moduleName));
        return await RunAsync(module, progress, ct, instanceKey).ConfigureAwait(false);
    }

    /// <summary>Runs every module concurrently; a slow or failing module does not block the others. A module with DependsOn or RunAfter
    /// waits for those that are part of the run; when a DependsOn didn't pass it is recorded as Skipped, and when one can't run here at all
    /// as Blocked (see <see cref="DependencyGate"/>). On-demand modules (<see cref="IDiagnosticModule.IncludeInRunAll"/> false) are left out.</summary>
    public Task<DiagnosticResult[]> RunAllAsync(CancellationToken ct = default) => RunSetAsync(Runnable.Where(m => m.IncludeInRunAll).ToArray(), ct);

    /// <summary>Runs one module after the DependsOn modules (and theirs) that haven't passed in this session; ones that already passed
    /// are not run again.</summary>
    public async Task<DiagnosticResult> RunWithDependenciesAsync(string moduleName, CancellationToken ct = default)
    {
        var target = FindRunnable(moduleName) ?? throw new ArgumentException($"Unknown module '{moduleName}'.", nameof(moduleName));
        var set = new List<IDiagnosticModule> { target };
        var queue = new Queue<Guid>(DescriptorOf(target).DependsOn);
        var seen = new HashSet<Guid> { target.Id };
        while (queue.TryDequeue(out var id))
        {
            if (!seen.Add(id)) continue;
            if (Modules.FirstOrDefault(m => m.Id == id) is not { } dep || ModuleOrdering.Passed(_store.Get(dep.Name))) continue;
            set.Add(dep);
            foreach (var next in DescriptorOf(dep).DependsOn) queue.Enqueue(next);
        }
        var results = await RunSetAsync(set, ct).ConfigureAwait(false);
        return results[0];
    }

    private ModuleDescriptor DescriptorOf(IDiagnosticModule m) =>
        Catalog.Get(m.Id) ?? new ModuleDescriptor(m.Id, m.Name, m.DisplayName, m.IncludeInRunAll ? ModuleKind.Check : ModuleKind.OnDemand);

    /// <summary>Runs <paramref name="modules"/> together in dependency order; results come back in the order given.</summary>
    private Task<DiagnosticResult[]> RunSetAsync(IReadOnlyList<IDiagnosticModule> modules, CancellationToken ct)
    {
        var byId = modules.GroupBy(m => m.Id).ToDictionary(g => g.Key, g => g.First());
        var tasks = new Dictionary<Guid, Task<DiagnosticResult>>();
        foreach (var d in ModuleOrdering.Sort(byId.Values.Select(DescriptorOf)))
            tasks[d.Id] = RunGatedAsync(byId[d.Id], d, tasks, ct);
        return Task.WhenAll(modules.Select(m => tasks[m.Id]));
    }

    private Task<DiagnosticResult> RunGatedAsync(IDiagnosticModule module, ModuleDescriptor d, IReadOnlyDictionary<Guid, Task<DiagnosticResult>> started, CancellationToken ct)
    {
        if (d.DependsOn.Count == 0 && !d.RunAfter.Any(started.ContainsKey)) return RunAsync(module, null, ct, gateInstances: true);
        // Taken now: every module this one waits for was started before it (topological order).
        var waitFor = d.DependsOn.Concat(d.RunAfter).Distinct().Where(started.ContainsKey).ToDictionary(id => id, id => started[id]);
        return WaitThenRunAsync();

        async Task<DiagnosticResult> WaitThenRunAsync()
        {
            var ran = new Dictionary<Guid, DiagnosticResult?>();
            foreach (var (id, t) in waitFor)
            {
                try { ran[id] = await t.ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { ran[id] = null; }
            }
            ct.ThrowIfCancellationRequested();
            // Per-device gating needs to know this module's devices (SharesDevices).
            if (module is IDetectableModule detectable && !_detections.ContainsKey(module.Id)) await DetectAsync(detectable).ConfigureAwait(false);
            if (GateFor(d, ran) is { } gate)
            {
                var r = ModuleOrdering.GateResult(module.Name, gate);
                _store.Set(r);
                try { Log.Info($"{module.Name}: {r.Message}"); } catch { }
                return r;
            }
            return await RunAsync(module, null, ct, gateInstances: true).ConfigureAwait(false);
        }
    }

    /// <summary>Why the module can't run now, or null. <paramref name="ranInThisRun"/> holds the results of modules that were part of the
    /// same run (null when one threw); a dependency outside the run counts when it passed earlier in this session.
    /// A per-device dependency that shares devices with a per-device module (<see cref="SharesDevices"/>) only blocks it here when it
    /// can't run at all; whether it passed is checked per device when the module runs (<see cref="InstanceGate"/>).</summary>
    public DependencyGate? GateFor(ModuleDescriptor d, IReadOnlyDictionary<Guid, DiagnosticResult?> ranInThisRun)
    {
        var dependent = _modules.FirstOrDefault(m => m.Id == d.Id);
        foreach (var dep in d.DependsOn)
            if (GateForDependency(dep, ranInThisRun) is { } gate && !(gate.Kind == GateKind.Skipped && PerDevicePair(dependent, dep) is not null)) return gate;
        return null;
    }

    /// <summary>True when both modules run per device and test some of the same devices (the same instance key): drive A's SMART check
    /// then gates only drive A's surface scan. Modules of one device class key their instances the same way.</summary>
    public bool SharesDevices(IDiagnosticModule a, IDiagnosticModule b) =>
        a is IPerDeviceModule && b is IPerDeviceModule && InstancesOf(a).Select(i => i.Key).Intersect(InstancesOf(b).Select(i => i.Key), StringComparer.OrdinalIgnoreCase).Any();

    private IDiagnosticModule? PerDevicePair(IDiagnosticModule? dependent, Guid dep) =>
        dependent is not null && _modules.FirstOrDefault(m => m.Id == dep) is { } depModule && SharesDevices(dependent, depModule) ? depModule : null;

    /// <summary>Why one device of a per-device module can't run: a per-device dependency that shares devices didn't pass on this same
    /// device, or (for a device it doesn't have) didn't pass on every device.</summary>
    private DependencyGate? InstanceGate(IDiagnosticModule module, ModuleInstance inst)
    {
        foreach (var dep in DescriptorOf(module).DependsOn)
        {
            if (PerDevicePair(module, dep) is not { } depModule) continue; // checked for the module as a whole
            var name = Catalog.Get(dep)?.DisplayName ?? depModule.DisplayName;
            var own = _store.GetInstance(depModule.Name, inst.Key);
            if (own is not null || InstancesOf(depModule).Any(i => string.Equals(i.Key, inst.Key, StringComparison.OrdinalIgnoreCase)))
            {
                if (!ModuleOrdering.Passed(own)) return new DependencyGate(GateKind.Skipped, $"{name} did not pass on this device", dep);
            }
            else if (!ModuleOrdering.Passed(_store.Get(depModule.Name)))
                return new DependencyGate(GateKind.Skipped, $"{name} did not pass", dep);
        }
        return null;
    }

    private static readonly IReadOnlyDictionary<Guid, DiagnosticResult?> NothingRan = new Dictionary<Guid, DiagnosticResult?>();

    private DependencyGate? GateForDependency(Guid dep, IReadOnlyDictionary<Guid, DiagnosticResult?> ranInThisRun)
    {
        var name = Catalog.Get(dep)?.DisplayName ?? dep.ToString("D");
        if (ranInThisRun.TryGetValue(dep, out var r))
            return ModuleOrdering.Passed(r) ? null : new DependencyGate(GateKind.Skipped, $"{name} did not pass", dep);
        var state = Catalog.StateOf(dep);
        var runnable = Modules.FirstOrDefault(m => m.Id == dep);
        if (state != ModuleState.Available || runnable is null)
            return new DependencyGate(GateKind.Blocked, state switch
            {
                ModuleState.NotPresent => $"{name} doesn't apply to this PC",
                ModuleState.Disabled => $"{name} is turned off",
                _ when Catalog.Get(dep) is null => $"it needs module {dep:D}, which isn't installed",
                _ => $"{name} is no longer available",
            }, dep);
        return ModuleOrdering.Passed(_store.Get(runnable.Name)) ? null
            : new DependencyGate(GateKind.Skipped, $"{name} has not passed in this session", dep);
    }

    /// <summary>The DependsOn modules (and theirs) that haven't passed in this session, nearest first: what
    /// <see cref="RunWithDependenciesAsync"/> would run before <paramref name="moduleName"/> (Skipped), or what stops it (Blocked).
    /// Empty when every dependency has passed, or the module has none.</summary>
    public IReadOnlyList<DependencyGate> UnmetDependencies(string moduleName)
    {
        var target = Modules.FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));
        if (target is null) return [];
        var unmet = new List<DependencyGate>();
        var queue = new Queue<Guid>(DescriptorOf(target).DependsOn);
        var seen = new HashSet<Guid> { target.Id };
        while (queue.TryDequeue(out var id))
        {
            if (!seen.Add(id) || GateForDependency(id, NothingRan) is not { } gate) continue;
            unmet.Add(gate);
            if (gate.Kind == GateKind.Skipped && Modules.FirstOrDefault(m => m.Id == id) is { } dep)
                foreach (var next in DescriptorOf(dep).DependsOn) queue.Enqueue(next);
        }
        return unmet;
    }

    private void MarkRunning(IDiagnosticModule module)
    {
        _progress.TryRemove(module.Name, out _);
        _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, "Running…", DateTimeOffset.Now));
    }

    /// <summary>True while a run of the module is in flight.</summary>
    public bool IsRunning(string moduleName) => _inFlight.ContainsKey(moduleName);

    /// <summary>True while any module or the stress suite is running.</summary>
    public bool IsAnyRunning => !_inFlight.IsEmpty || IsStressSuiteRunning;

    /// <summary>Starts a run unless one is already in progress, in which case the in-flight task is returned (no double-runs).</summary>
    private Task<DiagnosticResult> RunAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct, string? onlyInstance = null, bool gateInstances = false)
    {
        Task<DiagnosticResult> task;
        lock (_gate)
        {
            if (!_inFlight.TryGetValue(module.Name, out var existing))
            {
                MarkRunning(module);
                var tcs = new TaskCompletionSource<DiagnosticResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                _inFlight[module.Name] = existing = tcs.Task;
                _ = Task.Run(async () =>
                {
                    DiagnosticResult? res = null;
                    Exception? err = null;
                    try { res = await RunCoreAsync(module, progress, ct, onlyInstance, gateInstances).ConfigureAwait(false); }
                    catch (Exception ex) { err = ex; }
                    finally
                    {
                        if (module is IStressSuiteModule stress) await CleanupStressAsync(stress).ConfigureAwait(false);
                        _inFlight.TryRemove(module.Name, out _);
                    }
                    if (err is not null) tcs.SetException(err);
                    else tcs.SetResult(res!);
                }, CancellationToken.None);
                return existing;
            }
            task = existing;
        }
        if (progress is not null)
        {
            if (_progress.TryGetValue(module.Name, out var current))
                progress.ReportStep(current.Step, current.Total, current.Message);
            void OnProgress(object? sender, (string ModuleName, CheckProgress? Progress) e)
            {
                if (string.Equals(e.ModuleName, module.Name, StringComparison.OrdinalIgnoreCase) && e.Progress is { } cp)
                    progress.ReportStep(cp.Step, cp.Total, cp.Message);
            }
            ProgressChanged += OnProgress;
            _ = task.ContinueWith(_ => ProgressChanged -= OnProgress, TaskScheduler.Default);
        }
        return ct.CanBeCanceled ? task.WaitAsync(ct) : task;
    }

    private async Task<DiagnosticResult> RunCoreAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct, string? onlyInstance, bool gateInstances)
    {
        var startedAt = _store.Get(module.Name) is { Status: DiagnosticStatus.Running } cur ? cur.Timestamp : DateTimeOffset.Now;
        var trackedProgress = CheckProgressExtensions.Create(cp =>
        {
            _progress[module.Name] = cp;
            if (!string.IsNullOrWhiteSpace(cp.Message))
                _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, cp.Message, startedAt));
            try { ProgressChanged?.Invoke(this, (module.Name, cp)); } catch { }
        }, progress);
        DiagnosticResult result;
        try
        {
            var availability = await module.CheckAvailabilityAsync(ct).ConfigureAwait(false);
            result = !availability.IsAvailable ? CouldNotRun.Result(module.Name, availability.Reason ?? "Couldn't run")
                : module is IPerDeviceModule perDevice ? await RunInstancesAsync(perDevice, trackedProgress, ct, onlyInstance, gateInstances).ConfigureAwait(false)
                : await module.RefreshAsync(trackedProgress, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now) { Cancelled = true };
        }
        catch (Exception ex)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Error, ex.Message, DateTimeOffset.Now, ex);
        }
        _progress.TryRemove(module.Name, out _);
        try { ProgressChanged?.Invoke(this, (module.Name, null)); } catch { }
        result = MarkStopped(module, result);
        _store.Set(result);
        return result;
    }

    /// <summary>One run per instance, one after another; each instance result is stored (and logged) on its own. The module's result is
    /// the worst of them, with the instance results as its payload. With <paramref name="onlyInstance"/> only that instance runs, and the
    /// module's result also counts the latest stored result of each other instance.</summary>
    private async Task<DiagnosticResult> RunInstancesAsync(IPerDeviceModule module, ICheckProgress progress, CancellationToken ct, string? onlyInstance = null, bool gateInstances = false)
    {
        if (!_detections.ContainsKey(module.Id)) await DetectAsync(module).ConfigureAwait(false);
        var all = InstancesOf(module);
        var instances = onlyInstance is null ? all : all.Where(i => string.Equals(i.Key, onlyInstance, StringComparison.OrdinalIgnoreCase)).ToList();
        if (instances.Count == 0)
            return CouldNotRun.Result(module.Name, onlyInstance is not null && all.Count > 0 ? "That device is no longer connected"
                : DetectionOf(module.Id)?.NotApplicableReason ?? "No hardware to test");
        var ran = new List<DiagnosticResult>(instances.Count);
        for (var i = 0; i < instances.Count; i++)
        {
            var inst = instances[i];
            ct.ThrowIfCancellationRequested();
            progress.Report(i + 1, instances.Count, inst.Label);
            _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, "Running…", DateTimeOffset.Now) { InstanceKey = inst.Key, InstanceLabel = inst.Label });
            DiagnosticResult r;
            if (gateInstances && InstanceGate(module, inst) is { } gate)
            {
                r = ModuleOrdering.GateResult(module.Name, gate);
                try { Log.Info($"{module.Name} ({inst.Label}): {r.Message}"); } catch { }
            }
            else
            {
                try { r = await module.RefreshAsync(inst, progress, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { r = new DiagnosticResult(module.Name, DiagnosticStatus.Error, ex.Message, DateTimeOffset.Now, ex); }
            }
            r = MarkStopped(module, r with { ModuleName = module.Name, InstanceKey = inst.Key, InstanceLabel = inst.Label });
            _store.Set(r);
            ran.Add(r);
            if (r.Cancelled) break;
        }
        // Every instance in detection order: this run's result, or the latest one from earlier.
        var results = all.Select(inst => ran.FirstOrDefault(r => r.InstanceKey == inst.Key) ?? Prior(inst.Key)).OfType<DiagnosticResult>().ToList();
        var worst = results.OrderByDescending(r => Severity(r.Status)).First();
        var message = results.Count == 1 ? worst.Message
            : results.All(r => r.Status == DiagnosticStatus.Ok) ? $"All {results.Count} passed"
            : $"{results.Count(r => r.Status != DiagnosticStatus.Ok)} of {results.Count} need attention: {worst.InstanceLabel}: {worst.Message}";
        object? summary = null;
        if (module is IInstanceSummary combiner)
        {
            try { summary = combiner.Combine(results); }
            catch (Exception ex) { try { Log.Warn($"{module.Name}: combining device results failed: {ex.Message}"); } catch { } }
        }
        return new DiagnosticResult(module.Name, worst.Status, message, DateTimeOffset.Now, new InstanceResults(results) { Summary = summary })
            { Cancelled = ran.Any(r => r.Cancelled) };

        DiagnosticResult? Prior(string key) =>
            _store.GetInstance(module.Name, key) is { Status: not (DiagnosticStatus.NotRun or DiagnosticStatus.Running) } prior ? prior : null;
        static int Severity(DiagnosticStatus s) => s switch { DiagnosticStatus.Error => 3, DiagnosticStatus.Warning => 2, DiagnosticStatus.Ok => 1, _ => 0 };
    }

    /// <summary>Runs the quick checks (<see cref="RunAllAsync"/>) and then the stress tests one after another
    /// (CPU, Memory, Disk, GPU, Network; never in parallel). Each test's Duration (and mode) is set for the run and
    /// restored afterwards. Unavailable tests are skipped; an overheated or failed test stops the sequence.
    /// Throws <see cref="InvalidOperationException"/> if a suite is already running.</summary>
    /// <param name="only">When set, only these stress tests run (suite order kept).</param>
    /// <param name="runQuickChecks">False skips the Run All quick checks before the stress tests.</param>
    public async Task<StressSuiteResult> RunStressSuiteAsync(StressSuiteMode mode, IProgress<StressSuiteProgress>? progress, CancellationToken ct = default,
        IReadOnlyCollection<string>? only = null, bool runQuickChecks = true)
    {
        if (Interlocked.CompareExchange(ref _suiteRunning, 1, 0) != 0)
            throw new InvalidOperationException("A stress test run is already in progress.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _suiteCts = cts;
        var modules = StressOrder
            .Where(n => only is null || only.Contains(n, StringComparer.OrdinalIgnoreCase))
            .Select(n => _modules.FirstOrDefault(m => string.Equals(m.Name, n, StringComparison.OrdinalIgnoreCase)) as IStressSuiteModule)
            .Where(m => m is not null).Cast<IStressSuiteModule>().ToList();
        var steps = modules.Select(m => new StressSuiteStep(m.Name, m.SuiteName, StressSuiteStepState.Pending)).ToArray();
        var label = StressSuite.RunLabel(mode);
        void Report(int index, bool finished, string? message)
        {
            var p = new StressSuiteProgress(mode, index, steps.Length, index > 0 && index <= steps.Length ? steps[index - 1].DisplayName : null, steps.ToArray(), finished, message);
            LastStressSuiteProgress = p;
            try { progress?.Report(p); } catch { }
            try { StressSuiteProgressChanged?.Invoke(this, p); } catch { }
        }
        StressSuiteResult Finish(StressSuiteOutcome outcome, string message, int from)
        {
            for (int j = from; j < steps.Length; j++)
                if (steps[j].State is StressSuiteStepState.Pending or StressSuiteStepState.Running)
                    steps[j] = steps[j] with { State = StressSuiteStepState.NotRun, Message = "Not run" };
            Report(steps.Length, true, message);
            CurrentSuiteLabel = null;
            Log.Info($"Stress suite ({label}) finished: {outcome} - {message} Steps: {string.Join("; ", steps.Select(s => $"{s.DisplayName}={s.State}"))}");
            return new StressSuiteResult(mode, outcome, steps.ToArray(), message);
        }
        try
        {
            CurrentSuiteLabel = label;
            Log.Info($"Stress suite ({label}) started");
            Report(0, false, null);
            if (runQuickChecks) await RunAllAsync(cts.Token).ConfigureAwait(false);
            for (int i = 0; i < modules.Count; i++)
            {
                var m = modules[i];
                if (cts.IsCancellationRequested) return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i);
                if (Catalog.Get(m.Id) is { DependsOn.Count: > 0 } descriptor)
                {
                    var ran = new Dictionary<Guid, DiagnosticResult?>();
                    for (var k = 0; k < i; k++)
                        ran[modules[k].Id] = steps[k].State is StressSuiteStepState.Passed or StressSuiteStepState.Problem ? _store.Get(modules[k].Name) : null;
                    if (GateFor(descriptor, ran) is { } gate)
                    {
                        var gr = ModuleOrdering.GateResult(m.Name, gate);
                        _store.Set(gr);
                        steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = gr.Message };
                        Log.Info($"Stress suite: {m.Name} {gr.Message}");
                        continue;
                    }
                }
                steps[i] = steps[i] with { State = StressSuiteStepState.Running };
                Report(i + 1, false, null);
                ModuleAvailability availability;
                try { availability = await m.CheckAvailabilityAsync(cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cts.IsCancellationRequested) { return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i); }
                catch (Exception ex) { availability = ModuleAvailability.Unavailable(ex.Message); }
                if (!availability.IsAvailable)
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = "Skipped: not available on this PC" };
                    Log.Info($"Stress suite: {m.Name} skipped (unavailable: {availability.Reason})");
                    continue;
                }
                var saved = m.SaveSuiteSettings();
                DiagnosticResult r;
                try
                {
                    m.ApplySuiteMode(mode);
                    using (cts.Token.Register(() => { try { m.Stop(); } catch { } }))
                    {
                        var hung = await RunWithWatchdogAsync(m, cts.Token).ConfigureAwait(false);
                        if (hung.Result is null)
                        {
                            steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = hung.Message };
                            Log.Info($"Stress suite: {m.Name} skipped ({hung.Message})");
                            if (cts.IsCancellationRequested) return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i + 1);
                            continue;
                        }
                        r = hung.Result;
                    }
                }
                finally
                {
                    try { m.RestoreSuiteSettings(saved); } catch (Exception ex) { Log.Warn($"Stress suite: restoring {m.Name} settings failed: {ex.Message}"); }
                }
                _suiteLabels[m.Name] = (r.Timestamp, label);
                if (cts.IsCancellationRequested || m.IsStoppedByUserResult(r))
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.NotRun, Message = "Stopped" };
                    return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i + 1);
                }
                if (m.IsUnavailableResult(r))
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = "Skipped: not available on this PC" };
                    continue;
                }
                if (!m.IsOverheatedResult(r) && m.IsCouldNotRunResult(r))
                {
                    // Couldn't run (e.g. not enough free memory) is not a hardware problem: skip it and run the rest.
                    steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = $"Skipped: {r.Message}" };
                    Log.Warn($"Stress suite: {m.Name} skipped (couldn't run: {r.Message})");
                    continue;
                }
                if (r.Status == DiagnosticStatus.Error || m.IsOverheatedResult(r))
                {
                    var hot = m.IsOverheatedResult(r);
                    steps[i] = steps[i] with { State = StressSuiteStepState.Problem, Message = r.Message };
                    return Finish(StressSuiteOutcome.StoppedOnProblem, (hot
                        ? $"Stress tests stopped: the PC got too hot during the {m.SuiteName} test. The remaining tests were not run."
                        : $"Stress tests stopped: the {m.SuiteName} test found a problem ({r.Message}). The remaining tests were not run.") + SkippedNote(i), i + 1);
                }
                steps[i] = steps[i] with { State = r.Status == DiagnosticStatus.Ok ? StressSuiteStepState.Passed : StressSuiteStepState.Problem, Message = r.Message };
            }
            return Finish(StressSuiteOutcome.Completed, $"Stress tests finished ({label})." + SkippedNote(steps.Length), steps.Length);

            // " Skipped: Memory (couldn't run: not enough free memory)." for steps skipped so far (not "not available" ones).
            string SkippedNote(int upTo)
            {
                var parts = new List<string>();
                for (var k = 0; k < upTo && k < steps.Length; k++)
                    if (steps[k].State == StressSuiteStepState.Skipped && steps[k].Message is { } msg && msg.StartsWith("Skipped: ", StringComparison.Ordinal))
                        parts.Add($"{steps[k].DisplayName} ({msg["Skipped: ".Length..]})");
                return parts.Count == 0 ? "" : $" Skipped: {string.Join("; ", parts)}.";
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", 0);
        }
        finally
        {
            lock (_gate) _suiteCts = null;
            Volatile.Write(ref _suiteRunning, 0);
        }
    }
}

/// <summary>Payload of a per-device module's overall result: the result for each instance, in run order.</summary>
public sealed record InstanceResults(IReadOnlyList<DiagnosticResult> Results)
{
    /// <summary>The module's own combined report of all devices (<see cref="IInstanceSummary.Combine"/>), for pages that show one report.</summary>
    public object? Summary { get; init; }
}

/// <summary>
/// Optional on an <see cref="IPerDeviceModule"/>: folds the per-device results into the single report its page already knows how to show
/// (one AreaReport with a card per drive, one NpuTestReport listing every NPU). Read it with <see cref="InstanceResultExtensions.Report"/>.
/// </summary>
public interface IInstanceSummary
{
    /// <summary>The latest result of each device, in detection order. Never throws for a result without a payload.</summary>
    object? Combine(IReadOnlyList<DiagnosticResult> instanceResults);
}

public static class InstanceResultExtensions
{
    /// <summary>The payload to show for a module result: a per-device module's combined report, otherwise the payload itself.</summary>
    public static object? Report(this DiagnosticResult r) => r.Payload is InstanceResults ir ? ir.Summary : r.Payload;
}
