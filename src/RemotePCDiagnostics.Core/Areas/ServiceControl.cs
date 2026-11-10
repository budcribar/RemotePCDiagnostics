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
    private readonly object _gate = new();

    /// <summary>Raised after every action (success or failure), e.g. to notify the local user about a remote action.</summary>
    public event Action<ServiceActionRecord>? ActionCompleted;

    public IReadOnlyList<ServiceActionRecord> Recent { get { lock (_gate) return _recent.ToList(); } }

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
        var allowed = action == ServiceAction.Start ? opts.CanStart : action == ServiceAction.Stop ? opts.CanStop : opts.CanRestart;
        var what = s.Description.Length > 0 ? $"{s.Label}: {s.Description}" : $"{s.Label} is a Windows service.";
        IReadOnlyList<DependentService> deps = [];
        if (action != ServiceAction.Start)
        {
            try { deps = backend.GetRunningDependents(s.Name); }
            catch (Exception ex) { LogError($"GetRunningDependents({s.Name}) failed: {ex}"); }
        }
        var happen = action switch
        {
            ServiceAction.Start => $"Windows will start {s.Label}.",
            ServiceAction.Stop => $"Windows will stop {s.Label}. Anything that relies on it may stop working until it is started again or the PC restarts.",
            _ => $"Windows will stop {s.Label} and then start it again. Anything that relies on it may pause briefly.",
        };
        string? warning = deps.Count == 0 ? null : action == ServiceAction.Stop
            ? $"These running services depend on it and will also be stopped: {string.Join(", ", deps.Select(d => d.Label))}."
            : $"These running services depend on it and will be stopped and started again: {string.Join(", ", deps.Select(d => d.Label))}.";
        if (!allowed) warning = Optimizations.MemorySuggestionEngine.IsVisualStudioCollector(s.Name) ? "Only changing the startup type to Manual is offered for the Visual Studio diagnostics collector." : opts.IsProtected ? $"{s.Label} is protected by Windows and can't be changed from here." : $"{s.Label} can't be {Past(action)} right now.";
        return new(action, $"{Verb(action)} {s.Label}?", what, happen, deps, warning, allowed);
    }

    public async Task<ServiceActionResult> ExecuteAsync(ServiceInfo s, ServiceAction action, CancellationToken ct = default)
    {
        var actor = Actor;
        Log($"{actor} requested {action} of '{s.Name}' ({s.Label})");
        ServiceActionResult result;
        var opts = OptionsFor(s);
        var allowed = action == ServiceAction.Start ? opts.CanStart : action == ServiceAction.Stop ? opts.CanStop : opts.CanRestart;
        if (!allowed && !opts.IsProtected && StatusText(SafeState(s.Name)) is { Length: > 0 } live && live != s.Status)
        {
            s = s with { Status = live };
            opts = OptionsFor(s);
            allowed = action == ServiceAction.Start ? opts.CanStart : action == ServiceAction.Stop ? opts.CanStop : opts.CanRestart;
        }
        if (!allowed)
        {
            Log($"Refused {action} of '{s.Name}': protected={opts.IsProtected} status={s.Status} startType={s.StartType}");
            result = new(false, Optimizations.MemorySuggestionEngine.IsVisualStudioCollector(s.Name) ? "Only changing the startup type to Manual is offered for the Visual Studio diagnostics collector." : opts.IsProtected ? $"{s.Label} is protected by Windows and can't be {Past(action)} from here." : $"{s.Label} can't be {Past(action)} right now.", SafeState(s.Name));
        }
        else
        {
            result = await RunAsync(s, action, ct).ConfigureAwait(false);
        }
        if (result.Success && action is ServiceAction.Start or ServiceAction.Stop)
            try { journal?.Add(Changes.ChangeRecord.New(Changes.ChangeKind.ServiceRunning, s.Name, action == ServiceAction.Stop ? "Running" : "Stopped", $"{s.Label} {(action == ServiceAction.Stop ? "stopped" : "started")}", actor)); } catch { }
        var rec = new ServiceActionRecord(DateTime.Now, actor, action, s.Name, s.Label, result.Success, result.Message);
        lock (_gate)
        {
            _recent.Insert(0, rec);
            if (_recent.Count > MaxRecent) _recent.RemoveAt(_recent.Count - 1);
        }
        Log($"AUDIT when={rec.When:O} actor='{actor}' action={action} service='{s.Name}' success={result.Success} newState={result.NewState} message='{result.Message}'");
        try { ActionCompleted?.Invoke(rec); } catch (Exception ex) { LogError($"ActionCompleted handler failed: {ex}"); }
        return result;
    }

    private ServiceState SafeState(string name)
    {
        try { return backend.GetState(name); } catch (Exception ex) { LogError($"GetState({name}) failed: {ex}"); return ServiceState.Unknown; }
    }

    private async Task<ServiceActionResult> RunAsync(ServiceInfo s, ServiceAction action, CancellationToken ct)
    {
        var verb = Lower(action);
        string step = verb;
        try
        {
            IReadOnlyList<DependentService> deps = [];
            if (action != ServiceAction.Start) deps = backend.GetRunningDependents(s.Name);
            if (action is ServiceAction.Stop or ServiceAction.Restart)
            {
                step = "stop";
                backend.Stop(s.Name);
                if (!await backend.WaitForStateAsync(s.Name, ServiceState.Stopped, Timeout, ct).ConfigureAwait(false))
                {
                    LogWarn($"Timed out after {Timeout.TotalSeconds:0}s waiting for '{s.Name}' to stop");
                    return new(false, $"Couldn't {verb} {s.Label}: it didn't respond in time.", SafeState(s.Name));
                }
            }
            if (action is ServiceAction.Start or ServiceAction.Restart)
            {
                step = "start";
                backend.Start(s.Name);
                if (!await backend.WaitForStateAsync(s.Name, ServiceState.Running, Timeout, ct).ConfigureAwait(false))
                {
                    LogWarn($"Timed out after {Timeout.TotalSeconds:0}s waiting for '{s.Name}' to start");
                    return new(false, $"Couldn't {verb} {s.Label}: it didn't respond in time.", SafeState(s.Name));
                }
                if (action == ServiceAction.Restart)
                {
                    foreach (var d in deps)
                    {
                        try
                        {
                            backend.Start(d.Name);
                            await backend.WaitForStateAsync(d.Name, ServiceState.Running, Timeout, ct).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException) { LogError($"Restarting dependent '{d.Name}' failed: {ex}"); }
                    }
                }
            }
            return new(true, $"{s.Label} {Past(action)}", SafeState(s.Name));
        }
        catch (OperationCanceledException)
        {
            Log($"{action} of '{s.Name}' cancelled during {step}");
            return new(false, $"Stopped waiting for {s.Label}. Windows may still finish the change in the background.", SafeState(s.Name));
        }
        catch (Exception ex)
        {
            LogError($"{action} of '{s.Name}' failed during {step}: {ex}");
            var why = s.IsDisabled && step == "start" ? "it's turned off (disabled)" : "Windows didn't allow it";
            return new(false, $"Couldn't {verb} {s.Label}: {why}.", SafeState(s.Name));
        }
    }

    /// <summary>Friendly status word for a live state (matches <see cref="ServiceInfo.FriendlyStatus"/>).</summary>
    public static string StatusText(ServiceState st) => st switch
    {
        ServiceState.Running => "RUNNING", ServiceState.Stopped => "STOPPED", ServiceState.Paused => "PAUSED",
        ServiceState.StartPending => "START_PENDING", ServiceState.StopPending => "STOP_PENDING",
        ServiceState.ContinuePending => "CONTINUE_PENDING", ServiceState.PausePending => "PAUSE_PENDING", _ => "",
    };
}
