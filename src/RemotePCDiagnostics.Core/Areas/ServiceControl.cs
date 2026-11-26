using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Live state of a service as seen by the service control manager.</summary>
public enum ServiceState { Unknown, Stopped, StartPending, StopPending, Running, ContinuePending, PausePending, Paused, NotFound }

/// <summary>A dependent service (one that needs the target service to be running).</summary>
public sealed record DependentService(string Name, string DisplayName)
{
    public string Label => DisplayName.Length > 0 ? DisplayName : Name;
}

/// <summary>
/// Thin abstraction over <c>System.ServiceProcess.ServiceController</c> so the action logic can be tested with fakes.
/// The Windows implementation lives in the Host. Methods may throw; callers translate failures to plain messages.
/// </summary>
public interface IServiceControlBackend
{
    ServiceState GetState(string name);
    /// <summary>True when the entry is a kernel or file-system driver rather than a Win32 service.</summary>
    bool IsDriver(string name);
    IReadOnlyList<DependentService> GetRunningDependents(string name);
    void Start(string name);
    /// <summary>Stops the service (Windows stops running dependent services first).</summary>
    void Stop(string name);
    /// <summary>Waits until the service reaches <paramref name="target"/>; false on timeout.</summary>
    Task<bool> WaitForStateAsync(string name, ServiceState target, TimeSpan timeout, CancellationToken ct);
}

public enum ServiceAction { Start, Stop, Restart }

/// <summary>Which buttons a service row gets.</summary>
public sealed record ServiceControlOptions(bool CanStart, bool CanStop, bool CanRestart, bool IsProtected, string? ProtectedText);

/// <summary>Hard-coded list of services the app never stops or restarts.</summary>
public static class ServiceProtection
{
    public const string ProtectedText = "Protected by Windows";

    /// <summary>Core Windows services: stopping any of these can crash, lock up, or disconnect the PC.</summary>
    public static readonly IReadOnlySet<string> Protected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "DcomLaunch", "RpcEptMapper", "LSM", "SamSs", "lsass", "KeyIso", "VaultSvc", "Netlogon", "EFS",
        "EventLog", "Winmgmt", "CryptSvc", "BFE", "mpssvc", "WinDefend", "wscsvc", "SecurityHealthService", "Sense", "WdNisSvc", "MdCoreSvc",
        "Dhcp", "Dnscache", "NlaSvc", "nsi", "Power", "PlugPlay", "ProfSvc", "UserManager", "gpsvc", "Schedule",
        "TrustedInstaller", "BrokerInfrastructure", "SystemEventsBroker", "CoreMessagingRegistrar", "StateRepository",
        "TimeBrokerSvc", "AudioEndpointBuilder", "Appinfo", "LanmanWorkstation", "TermService", "UmRdpService", "SessionEnv",
        "WinHttpAutoProxySvc", "Wcmsvc", "msiserver", "sppsvc", "EventSystem", "SENS", "Themes", "DeviceInstall", "camsvc",
    };

    /// <summary>Name fragments of this app's own remote-session components (never stopped from inside the session).</summary>
    public static readonly IReadOnlyList<string> SelfComponents = ["RemotePCDiagnostics", "RemoteWebView", "RemoteBlazor", "PeakSWC"];

    public static bool IsProtected(string name) => Protected.Contains(name);

    /// <summary>
    /// The two Windows Audio services: protected from being stopped, but the Sound check may set a disabled one back to Automatic (and
    /// undo may put it back), since no sound plays while either is disabled. Starting and restarting them has its own Agent script.
    /// </summary>
    public static readonly IReadOnlySet<string> AudioStartTypeChangeable = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "Audiosrv", "AudioEndpointBuilder" };

    /// <summary>True when the app must not change <paramref name="name"/>'s start-up type.</summary>
    public static bool ProtectsStartType(string name) =>
        (IsProtected(name) || IsSelfComponent(name)) && !AudioStartTypeChangeable.Contains(name);
    public static bool IsSelfComponent(string name) => SelfComponents.Any(f => name.Contains(f, StringComparison.OrdinalIgnoreCase));

    public static ServiceControlOptions For(ServiceInfo s, bool isDriver = false)
    {
        // The collector is Manual-only throughout the app; generic service controls must not bypass that policy.
        var collector = Optimizations.MemorySuggestionEngine.IsVisualStudioCollector(s.Name);
        var locked = isDriver || IsProtected(s.Name) || IsSelfComponent(s.Name) || collector;
        var running = s.IsRunning;
        var stopped = s.IsStopped;
        // Start is allowed for a stopped protected service (it only brings Windows back to normal); never for drivers or disabled services.
        var canStart = stopped && !s.IsDisabled && !isDriver && !IsSelfComponent(s.Name);
        return new(canStart, running && !locked, running && !locked, locked, collector ? "Manual-only: change startup type without stopping the collector" : locked ? ProtectedText : null);
    }
}

/// <summary>Who triggered an action.</summary>
public static class ServiceActor
{
    public const string Local = "Local user";
    public const string Remote = "Remote user";
    /// <summary>In Remote mode the UI is driven from the remote user's browser, so actions are attributed to the remote user.</summary>
    public static string From(ISessionContext? session) => session?.Mode == SessionMode.Remote ? Remote : Local;
}

public sealed record ServiceActionRecord(DateTime When, string Actor, ServiceAction Action, string ServiceName, string ServiceLabel, bool Success, string Message);

public sealed record ServiceActionResult(bool Success, string Message, ServiceState NewState);

/// <summary>Confirmation text shown before acting.</summary>
public sealed record ServiceActionPlan(ServiceAction Action, string Title, string WhatItIs, string WhatWillHappen, IReadOnlyList<DependentService> Dependents, string? Warning, bool Allowed);

/// <summary>Plans, runs and audits start/stop/restart of Windows services. All user-facing text is plain; detail goes to the log.</summary>
public sealed class ServiceActionService(IServiceControlBackend backend, ISessionContext? session = null, ILogger? log = null, TimeSpan? timeout = null,
    Changes.IChangeJournal? journal = null)
{
    public const int MaxRecent = 20;
    public TimeSpan Timeout { get; } = timeout ?? TimeSpan.FromSeconds(30);
    private readonly List<ServiceActionRecord> _recent = [];
    private volatile IReadOnlyList<ServiceActionRecord> _recentSnapshot = [];
    private readonly object _gate = new();

    /// <summary>Raised after every action (success or failure), e.g. to notify the local user about a remote action.</summary>
    public event Action<ServiceActionRecord>? ActionCompleted;

    public IReadOnlyList<ServiceActionRecord> Recent => _recentSnapshot;

    public string Actor => ServiceActor.From(session);

    private void Log(string m) => log.Info("[services] " + m);
    private void LogWarn(string m) => log.Warn("[services] " + m);
    private void LogError(string m) => log.Error("[services] " + m);

    public ServiceControlOptions OptionsFor(ServiceInfo s)
    {
        bool driver;
        try { driver = backend.IsDriver(s.Name); } catch (Exception ex) { LogError($"IsDriver({s.Name}) failed: {ex}"); driver = false; }
        return ServiceProtection.For(s, driver);
    }

    public static string Verb(ServiceAction a) => a switch { ServiceAction.Start => "Start", ServiceAction.Stop => "Stop", _ => "Restart" };
    private static string Past(ServiceAction a) => a switch { ServiceAction.Start => "started", ServiceAction.Stop => "stopped", _ => "restarted" };
    private static string Lower(ServiceAction a) => Verb(a).ToLowerInvariant();

    public ServiceActionPlan Plan(ServiceInfo s, ServiceAction action)
    {
        var opts = OptionsFor(s);
        var allowed = IsActionAllowed(opts, action);
        var what = s.Description.Length > 0 ? $"{s.Label}: {s.Description}" : $"{s.Label} is a Windows service.";
        var deps = GetRunningDependentsSafe(s.Name, action);
        var happen = DescribeAction(s.Label, action);
        var warning = allowed
            ? BuildDependentsWarning(deps, action)
            : BuildRefusalMessage(s, opts, action);
        return new(action, $"{Verb(action)} {s.Label}?", what, happen, deps, warning, allowed);
    }

    public async Task<ServiceActionResult> ExecuteAsync(ServiceInfo s, ServiceAction action, CancellationToken ct = default)
    {
        var actor = Actor;
        Log($"{actor} requested {action} of '{s.Name}' ({s.Label})");
        (s, var opts, var allowed) = RefreshOptionsIfStale(s, action);

        ServiceActionResult result;
        IReadOnlyList<DependentService> journaledStoppedDeps = [];
        var journalParentStopped = false;
        if (!allowed)
        {
            Log($"Refused {action} of '{s.Name}': protected={opts.IsProtected} status={s.Status} startType={s.StartType}");
            result = new(false, BuildRefusalMessage(s, opts, action, forExecution: true), SafeState(s.Name));
        }
        else
        {
            (result, journaledStoppedDeps, journalParentStopped) = await RunAsync(s, action, ct).ConfigureAwait(false);
        }

        RecordJournalEntries(s, action, actor, result.Success, journalParentStopped, journaledStoppedDeps);
        RecordRecentAction(s, action, actor, result);
        return result;
    }

    private static bool IsActionAllowed(ServiceControlOptions opts, ServiceAction action) => action switch
    {
        ServiceAction.Start => opts.CanStart,
        ServiceAction.Stop => opts.CanStop,
        _ => opts.CanRestart,
    };

    private IReadOnlyList<DependentService> GetRunningDependentsSafe(string serviceName, ServiceAction action)
    {
        if (action == ServiceAction.Start) return [];
        try { return backend.GetRunningDependents(serviceName); }
        catch (Exception ex) { LogError($"GetRunningDependents({serviceName}) failed: {ex}"); return []; }
    }

    private static string DescribeAction(string label, ServiceAction action) => action switch
    {
        ServiceAction.Start => $"Windows will start {label}.",
        ServiceAction.Stop => $"Windows will stop {label}. Anything that relies on it may stop working until it is started again or the PC restarts.",
        _ => $"Windows will stop {label} and then start it again. Anything that relies on it may pause briefly.",
    };

    private static string? BuildDependentsWarning(IReadOnlyList<DependentService> deps, ServiceAction action)
    {
        if (deps.Count == 0) return null;
        var names = string.Join(", ", deps.Select(d => d.Label));
        return action == ServiceAction.Stop
            ? $"These running services depend on it and will also be stopped: {names}."
            : $"These running services depend on it and will be stopped and started again: {names}.";
    }

    private static string BuildRefusalMessage(ServiceInfo s, ServiceControlOptions opts, ServiceAction action, bool forExecution = false)
    {
        if (Optimizations.MemorySuggestionEngine.IsVisualStudioCollector(s.Name))
            return "Only changing the startup type to Manual is offered for the Visual Studio diagnostics collector.";
        if (opts.IsProtected)
            return forExecution
                ? $"{s.Label} is protected by Windows and can't be {Past(action)} from here."
                : $"{s.Label} is protected by Windows and can't be changed from here.";
        return $"{s.Label} can't be {Past(action)} right now.";
    }

    private (ServiceInfo Service, ServiceControlOptions Options, bool Allowed) RefreshOptionsIfStale(ServiceInfo s, ServiceAction action)
    {
        var opts = OptionsFor(s);
        var allowed = IsActionAllowed(opts, action);
        if (!allowed && !opts.IsProtected && StatusText(SafeState(s.Name)) is { Length: > 0 } live && live != s.Status)
        {
            s = s with { Status = live };
            opts = OptionsFor(s);
            allowed = IsActionAllowed(opts, action);
        }
        return (s, opts, allowed);
    }

    private void RecordJournalEntries(
        ServiceInfo s,
        ServiceAction action,
        string actor,
        bool success,
        bool journalParentStopped,
        IReadOnlyList<DependentService> journaledStoppedDeps)
    {
        if (journal is null) return;
        try
        {
            var nowUtc = DateTimeOffset.UtcNow;
            if (action == ServiceAction.Start && success)
            {
                journal.Add(new(Guid.NewGuid(), nowUtc, Changes.ChangeKind.ServiceRunning, s.Name, "Stopped", $"{s.Label} started", actor));
                return;
            }
            if (!journalParentStopped && journaledStoppedDeps.Count == 0) return;

            // Reverse order so UndoAllAsync (which replays last-added first) starts the parent first, then direct dependents, then leaf dependents.
            foreach (var d in Enumerable.Reverse(journaledStoppedDeps))
                journal.Add(new(Guid.NewGuid(), nowUtc, Changes.ChangeKind.ServiceRunning, d.Name, "Running", $"{d.Label} stopped (depends on {s.Label})", actor));
            if (journalParentStopped)
                journal.Add(new(Guid.NewGuid(), nowUtc, Changes.ChangeKind.ServiceRunning, s.Name, "Running", $"{s.Label} stopped", actor));
        }
        catch { }
    }

    private void RecordRecentAction(ServiceInfo s, ServiceAction action, string actor, ServiceActionResult result)
    {
        var rec = new ServiceActionRecord(DateTime.Now, actor, action, s.Name, s.Label, result.Success, result.Message);
        lock (_gate)
        {
            _recent.Insert(0, rec);
            if (_recent.Count > MaxRecent) _recent.RemoveAt(_recent.Count - 1);
            _recentSnapshot = _recent.ToArray();
        }
        Log($"AUDIT when={rec.When:O} actor='{actor}' action={action} service='{s.Name}' success={result.Success} newState={result.NewState} message='{result.Message}'");
        try { ActionCompleted?.Invoke(rec); } catch (Exception ex) { LogError($"ActionCompleted handler failed: {ex}"); }
    }

    private ServiceState SafeState(string name)
    {
        try { return backend.GetState(name); } catch (Exception ex) { LogError($"GetState({name}) failed: {ex}"); return ServiceState.Unknown; }
    }

    private async Task<(ServiceActionResult Result, IReadOnlyList<DependentService> StoppedDeps, bool ParentStopped)> RunAsync(ServiceInfo s, ServiceAction action, CancellationToken ct)
    {
        var verb = Lower(action);
        string step = verb;
        IReadOnlyList<DependentService> deps = [];
        var stopped = false;
        try
        {
            if (action != ServiceAction.Start) deps = backend.GetRunningDependents(s.Name);
            if (action is ServiceAction.Stop or ServiceAction.Restart)
            {
                step = "stop";
                var stopFailure = await StopServiceAsync(s, verb, ct).ConfigureAwait(false);
                if (stopFailure is not null) return (stopFailure, [], false);
                stopped = true;
            }
            if (action is ServiceAction.Start or ServiceAction.Restart)
            {
                step = "start";
                var startOutcome = await StartAndRecoverDependentsAsync(s, action, verb, deps, stopped, ct).ConfigureAwait(false);
                if (startOutcome is not null) return startOutcome.Value;
            }
            return (new(true, $"{s.Label} {Past(action)}", SafeState(s.Name)),
                action == ServiceAction.Stop ? deps : [], action == ServiceAction.Stop);
        }
        catch (OperationCanceledException)
        {
            Log($"{action} of '{s.Name}' cancelled during {step}");
            var leftStopped = stopped && step == "start";
            return (new(false, $"Stopped waiting for {s.Label}. Windows may still finish the change in the background.", SafeState(s.Name)),
                leftStopped ? deps : [], leftStopped);
        }
        catch (Exception ex)
        {
            return HandleRunException(s, action, verb, step, deps, stopped, ex);
        }
    }

    private async Task<ServiceActionResult?> StopServiceAsync(ServiceInfo s, string verb, CancellationToken ct)
    {
        backend.Stop(s.Name);
        if (await backend.WaitForStateAsync(s.Name, ServiceState.Stopped, Timeout, ct).ConfigureAwait(false))
            return null;
        LogWarn($"Timed out after {Timeout.TotalSeconds:0}s waiting for '{s.Name}' to stop");
        return new(false, $"Couldn't {verb} {s.Label}: it didn't respond in time.", SafeState(s.Name));
    }

    private async Task<(ServiceActionResult Result, IReadOnlyList<DependentService> StoppedDeps, bool ParentStopped)?> StartAndRecoverDependentsAsync(
        ServiceInfo s, ServiceAction action, string verb, IReadOnlyList<DependentService> deps, bool stopped, CancellationToken ct)
    {
        backend.Start(s.Name);
        if (!await backend.WaitForStateAsync(s.Name, ServiceState.Running, Timeout, ct).ConfigureAwait(false))
        {
            LogWarn($"Timed out after {Timeout.TotalSeconds:0}s waiting for '{s.Name}' to start");
            return (new(false, $"Couldn't {verb} {s.Label}: it didn't respond in time.", SafeState(s.Name)),
                stopped ? deps : [], stopped);
        }

        if (action != ServiceAction.Restart) return null;

        var failedDeps = await RestartDependentsAsync(deps, ct).ConfigureAwait(false);
        if (failedDeps.Count == 0) return null;

        var names = string.Join(", ", failedDeps.Select(d => d.Label));
        var noun = failedDeps.Count == 1 ? "service" : "services";
        return (new(false, $"{s.Label} restarted, but couldn't start dependent {noun}: {names}.", SafeState(s.Name)),
            failedDeps, false);
    }

    private async Task<List<DependentService>> RestartDependentsAsync(IReadOnlyList<DependentService> deps, CancellationToken ct)
    {
        var failedDeps = new List<DependentService>();
        foreach (var d in deps)
        {
            if (!await TryStartDependentAsync(d, ct).ConfigureAwait(false))
                failedDeps.Add(d);
        }
        return failedDeps;
    }

    private async Task<bool> TryStartDependentAsync(DependentService d, CancellationToken ct)
    {
        try
        {
            backend.Start(d.Name);
            if (await backend.WaitForStateAsync(d.Name, ServiceState.Running, Timeout, ct).ConfigureAwait(false))
                return true;
            LogWarn($"Timed out after {Timeout.TotalSeconds:0}s waiting for dependent '{d.Name}' to start");
            return false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError($"Restarting dependent '{d.Name}' failed: {ex}");
            return false;
        }
    }

    private (ServiceActionResult Result, IReadOnlyList<DependentService> StoppedDeps, bool ParentStopped) HandleRunException(
        ServiceInfo s, ServiceAction action, string verb, string step, IReadOnlyList<DependentService> deps, bool stopped, Exception ex)
    {
        LogError($"{action} of '{s.Name}' failed during {step}: {ex}");
        var why = ex is AdminRequiredException
            ? ex.Message
            : s.IsDisabled && step == "start" ? "it's turned off (disabled)." : "Windows didn't allow it.";
        var leftStopped = stopped && step == "start";
        return (new(false, $"Couldn't {verb} {s.Label}: {why}", SafeState(s.Name)),
            leftStopped ? deps : [], leftStopped);
    }

    /// <summary>Friendly status word for a live state (matches <see cref="ServiceInfo.FriendlyStatus"/>).</summary>
    public static string StatusText(ServiceState st) => st switch
    {
        ServiceState.Running => "RUNNING", ServiceState.Stopped => "STOPPED", ServiceState.Paused => "PAUSED",
        ServiceState.StartPending => "START_PENDING", ServiceState.StopPending => "STOP_PENDING",
        ServiceState.ContinuePending => "CONTINUE_PENDING", ServiceState.PausePending => "PAUSE_PENDING", _ => "",
    };
}
