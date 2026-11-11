using System.Collections.Concurrent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

// RemotePCDiagnostics.ModuleHost "<module.dll>" | --shared
// Loads one module (or, with --shared, any number of bundled modules of the same token level) into its own load context and answers the
// app's requests (one JSON line each) until stdin closes or "exit".
// Everything here runs with the token the app gave it: a restricted one (no administrator, Medium integrity), or for a module that ships
// with the app and needs administrator, the app's own (out of process for crash and memory isolation only). A module in user mode asks
// the app for what needs administrator rights (host queries: "query" lines out, "answer" lines back).
if (args.Length < 1) { Console.Error.WriteLine("usage: RemotePCDiagnostics.ModuleHost <module.dll> | --shared"); return 2; }

// The protocol owns stdout; anything the module prints goes to stderr (the app's log).
var output = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = false };
Console.SetOut(Console.Error);
// The app writes UTF-8; Console.In would decode with the console's code page.
var input = new StreamReader(Console.OpenStandardInput(), new System.Text.UTF8Encoding(false));
var writeGate = new object();
void SendRaw(ModuleHostMessage m)
{
    if (m.Type == "query") Console.Error.WriteLine($"query {m.Id} {m.Capability} sent");
    lock (writeGate) { output.WriteLine(m.ToLine()); output.Flush(); }
}

// A module that ships with the app may reference the app's own assemblies (its details page derives from the UI's ModuleDetailsBase).
// This host never renders that page, but registering it loads the type, so those assemblies resolve from the app folder next to this exe.
System.Runtime.Loader.AssemblyLoadContext.Default.Resolving += (context, name) =>
{
    var file = Path.Combine(AppContext.BaseDirectory, (name.Name ?? "") + ".dll");
    return name.Name is { Length: > 0 } && name.Name.StartsWith("RemotePCDiagnostics.", StringComparison.Ordinal) && File.Exists(file)
        ? context.LoadFromAssemblyPath(file) : null;
};

if (args[0] == "--shared")
{
    var sessions = new ConcurrentDictionary<string, ModuleSession>(StringComparer.OrdinalIgnoreCase);
    var initLocks = new ConcurrentDictionary<string, object>(StringComparer.OrdinalIgnoreCase);

    ModuleSession? GetOrCreateSession(string modulePath)
    {
        if (sessions.TryGetValue(modulePath, out var existing)) return existing;
        var gate = initLocks.GetOrAdd(modulePath, _ => new object());
        lock (gate)
        {
            if (sessions.TryGetValue(modulePath, out existing)) return existing;
            void SendTagged(ModuleHostMessage m) => SendRaw(m with { Module = modulePath });
            var q = new HostQueriesClient(SendTagged);
            try
            {
                var loaded = UserModePlugin.Load(modulePath, new RemotePCDiagnostics.Logging.LineLogger(line => Console.Error.WriteLine(line)), AppContext.BaseDirectory, q).Module;
                var created = new ModuleSession(loaded, q, SendTagged);
                sessions[modulePath] = created;
                return created;
            }
            catch (Exception ex)
            {
                SendTagged(new ModuleHostMessage { Type = "error", Message = $"Couldn't load the module: {ex.GetType().Name}: {ex.Message}" });
                return null;
            }
        }
    }

    while (input.ReadLine() is { } line)
    {
        var request = ModuleHostMessage.Parse(line);
        if (request is null)
        {
            if (!string.IsNullOrWhiteSpace(line)) Console.Error.WriteLine($"unreadable request ({line.Length} chars) ignored");
            continue;
        }
        if (request.Type == "exit" && string.IsNullOrEmpty(request.Module))
            break;
        if (string.IsNullOrEmpty(request.Module))
            continue;
        if (request.Type == "exit")
        {
            if (sessions.TryGetValue(request.Module, out var s)) s.ExitVirtual();
            continue;
        }
        var session = GetOrCreateSession(request.Module);
        session?.Handle(request);
    }

    foreach (var s in sessions.Values) s.Shutdown();
    return 0;
}
else
{
    var queries = new HostQueriesClient(SendRaw);
    IDiagnosticModule module;
    // This exe sits in the app's folder, so the app's helpers (osquery) resolve from here.
    try { module = UserModePlugin.Load(args[0], new RemotePCDiagnostics.Logging.LineLogger(line => Console.Error.WriteLine(line)), AppContext.BaseDirectory, queries).Module; }
    catch (Exception ex)
    {
        SendRaw(new ModuleHostMessage { Type = "error", Message = $"Couldn't load the module: {ex.GetType().Name}: {ex.Message}" });
        return 1;
    }
    SendRaw(new ModuleHostMessage { Type = "ready", Message = module.Name });

    var session = new ModuleSession(module, queries, SendRaw);
    while (input.ReadLine() is { } line)
    {
        var request = ModuleHostMessage.Parse(line);
        if (request is null && !string.IsNullOrWhiteSpace(line)) Console.Error.WriteLine($"unreadable request ({line.Length} chars) ignored");
        if (request?.Type == "exit")
        {
            session.Shutdown();
            return 0;
        }
        if (request is not null) session.Handle(request);
    }
    session.Shutdown();
    return 0;
}

internal sealed class ModuleSession
{
    private sealed class RunState
    {
        public CancellationTokenSource Cts { get; } = new();
        public volatile bool Abandoned;
    }

    private readonly IDiagnosticModule _module;
    private readonly HostQueriesClient _queries;
    private readonly Action<ModuleHostMessage> _send;
    private readonly object _gate = new();
    private RunState? _currentRun;
    private CancellationTokenSource _sessionCts = new();
    private IReadOnlyList<ModuleInstance>? _devices;
    private readonly ConcurrentDictionary<string, DiagnosticResult> _deviceResults = new(StringComparer.OrdinalIgnoreCase);
    private Task? _refresh;
    private Task? _availability;

    public ModuleSession(IDiagnosticModule module, HostQueriesClient queries, Action<ModuleHostMessage> send)
    {
        _module = module;
        _queries = queries;
        _send = send;
        _module.Updated += OnUpdated;
    }

    private void OnUpdated(object? sender, DiagnosticResult r)
    {
        RunState? run;
        lock (_gate) run = _currentRun;
        if (run is null || run.Abandoned || run.Cts.IsCancellationRequested) return;
        var other = r.Payload is AreaReport ? null : ModuleHostPayloads.Write(r.Payload);
        _send(new ModuleHostMessage
        {
            Type = "updated",
            Status = r.Status,
            Message = r.Message,
            Cancelled = r.Cancelled,
            When = r.Timestamp,
            Report = r.Payload as AreaReport,
            Payload = other?.Payload,
            PayloadType = other?.Type,
            Instance = r.InstanceKey is { } key ? new ModuleInstance(key, r.InstanceLabel ?? key) : null,
        });
    }

    public void Handle(ModuleHostMessage request)
    {
        switch (request.Type)
        {
            case "answer":
                if (!_queries.Complete(request)) Console.Error.WriteLine($"answer {request.Id} arrived with no query waiting for it");
                break;
            case "availability":
                Task? previous;
                lock (_gate)
                {
                    previous = _availability;
                    _availability = Task.Run(async () =>
                    {
                        if (previous is not null) await previous.ConfigureAwait(false);
                        try
                        {
                            var a = await _module.CheckAvailabilityAsync();
                            _send(new ModuleHostMessage { Type = "availability", Available = a.IsAvailable, Reason = a.Reason });
                        }
                        catch (Exception ex) { _send(new ModuleHostMessage { Type = "availability", Available = false, Reason = ex.Message }); }
                    });
                }
                break;
            case "refresh":
                lock (_gate)
                {
                    Task? cancelling = null;
                    if (_refresh is { IsCompleted: false })
                    {
                        if (_currentRun is not { Abandoned: true })
                        {
                            _send(new ModuleHostMessage { Type = "error", Message = "already running" });
                            break;
                        }
                        cancelling = _refresh;
                    }
                    var run = new RunState();
                    _currentRun = run;
                    var ct = run.Cts.Token;
                    var instance = request.Instance;
                    void SendIfCurrent(ModuleHostMessage msg)
                    {
                        if (!run.Abandoned) _send(msg);
                    }
                    _refresh = Task.Run(async () =>
                    {
                        if (cancelling is not null)
                        {
                            try { await cancelling.ConfigureAwait(false); } catch { }
                        }
                        if (run.Abandoned) return;
                        var progress = CheckProgressExtensions.Create(p => SendIfCurrent(new ModuleHostMessage { Type = "progress", Message = p.Message, Step = p.Step, Total = p.Total }));
                        try
                        {
                            DiagnosticResult r;
                            Dictionary<string, System.Text.Json.JsonElement>? pageData;
                            if (instance is not null && _module is IPerDeviceModule perDevice)
                            {
                                r = await perDevice.RefreshAsync(instance, progress, ct);
                                _deviceResults[instance.Key] = r with { InstanceKey = instance.Key, InstanceLabel = instance.Label };
                                try { _devices = (await perDevice.DetectAsync(ct)).Instances; } catch (Exception ex) when (ex is not OperationCanceledException) { }
                                pageData = ModulePageCalls.Write(_module, _devices, _deviceResults);
                            }
                            else
                            {
                                r = await _module.RefreshAsync(progress, ct);
                                pageData = ModulePageCalls.Write(_module);
                            }
                            var other = r.Payload is AreaReport ? null : ModuleHostPayloads.Write(r.Payload);
                            SendIfCurrent(new ModuleHostMessage
                            {
                                Type = "result", Status = r.Status, Message = r.Message, Cancelled = r.Cancelled || ct.IsCancellationRequested, Report = r.Payload as AreaReport,
                                Payload = other?.Payload, PayloadType = other?.Type, PageData = pageData,
                            });
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested)
                        {
                            SendIfCurrent(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "Cancelled", Cancelled = true });
                        }
                        catch (Exception ex) { SendIfCurrent(new ModuleHostMessage { Type = "error", Message = $"{ex.GetType().Name}: {ex.Message}" }); }
                    });
                }
                break;
            case "detect":
                _ = Task.Run(async () =>
                {
                    try
                    {
                        if (_module is not IDetectableModule detectable) { _send(new ModuleHostMessage { Type = "detection", Reason = "This module doesn't run per device" }); return; }
                        var d = await detectable.DetectAsync();
                        _devices = d.Instances;
                        _send(new ModuleHostMessage { Type = "detection", Reason = d.NotApplicableReason, Instances = [.. d.Instances] });
                    }
                    catch (Exception ex) { _send(new ModuleHostMessage { Type = "detection", Reason = $"Detection failed: {ex.Message}" }); }
                });
                break;
            case "call":
                var call = request;
                CancellationToken callCt;
                lock (_gate) callCt = _sessionCts.Token;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var value = await ModulePageCalls.InvokeAsync(_module, call.Name ?? "", call.Args, callCt);
                        if (!callCt.IsCancellationRequested)
                            _send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = true, Value = value });
                    }
                    catch (OperationCanceledException) when (callCt.IsCancellationRequested) { }
                    catch (NotSupportedException ex) { if (!callCt.IsCancellationRequested) _send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = false, Error = "unknown", Reason = ex.Message }); }
                    catch (Exception ex) { if (!callCt.IsCancellationRequested) _send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = false, Error = "failed", Reason = $"{ex.GetType().Name}: {ex.Message}" }); }
                });
                break;
            case "stop":
                CancelRunning();
                break;
        }
    }

    public void CancelRunning()
    {
        lock (_gate)
        {
            try { _currentRun?.Cts.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    public void ExitVirtual()
    {
        _queries.FailAll("the app closed the module host");
        CancellationTokenSource oldSession;
        lock (_gate)
        {
            if (_currentRun is { } run)
            {
                run.Abandoned = true;
                try { run.Cts.Cancel(); } catch (ObjectDisposedException) { }
            }
            oldSession = _sessionCts;
            _sessionCts = new CancellationTokenSource();
        }
        try { oldSession.Cancel(); } catch (ObjectDisposedException) { }
    }

    public void Shutdown()
    {
        _queries.FailAll("the app closed the module host");
        CancellationTokenSource session;
        lock (_gate)
        {
            if (_currentRun is { } run)
            {
                run.Abandoned = true;
                try { run.Cts.Cancel(); } catch (ObjectDisposedException) { }
            }
            session = _sessionCts;
        }
        try { session.Cancel(); } catch (ObjectDisposedException) { }
    }
}
