using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

// RemotePCDiagnostics.ModuleHost "<module.dll>"
// Loads one module into its own load context and answers the app's requests (one JSON line each) until stdin closes or "exit".
// Everything here runs with the token the app gave it: a restricted one (no administrator, Medium integrity), or for a module that ships
// with the app and needs administrator, the app's own (out of process for crash and memory isolation only). A module in user mode asks
// the app for what needs administrator rights (host queries: "query" lines out, "answer" lines back).
if (args.Length < 1) { Console.Error.WriteLine("usage: RemotePCDiagnostics.ModuleHost <module.dll>"); return 2; }

// The protocol owns stdout; anything the module prints goes to stderr (the app's log).
var output = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = false };
Console.SetOut(Console.Error);
// The app writes UTF-8; Console.In would decode with the console's code page.
var input = new StreamReader(Console.OpenStandardInput(), new System.Text.UTF8Encoding(false));
var writeGate = new object();
void Send(ModuleHostMessage m)
{
    if (m.Type == "query") Console.Error.WriteLine($"query {m.Id} {m.Capability} sent");
    lock (writeGate) { output.WriteLine(m.ToLine()); output.Flush(); }
}
var queries = new HostQueriesClient(Send);

// A module that ships with the app may reference the app's own assemblies (its details page derives from the UI's ModuleDetailsBase).
// This host never renders that page, but registering it loads the type, so those assemblies resolve from the app folder next to this exe.
System.Runtime.Loader.AssemblyLoadContext.Default.Resolving += (context, name) =>
{
    var file = Path.Combine(AppContext.BaseDirectory, (name.Name ?? "") + ".dll");
    return name.Name is { Length: > 0 } && name.Name.StartsWith("RemotePCDiagnostics.", StringComparison.Ordinal) && File.Exists(file)
        ? context.LoadFromAssemblyPath(file) : null;
};

IDiagnosticModule module;
// This exe sits in the app's folder, so the app's helpers (osquery) resolve from here.
try { module = UserModePlugin.Load(args[0], new RemotePCDiagnostics.Logging.LineLogger(line => Console.Error.WriteLine(line)), AppContext.BaseDirectory, queries).Module; }
catch (Exception ex)
{
    Send(new ModuleHostMessage { Type = "error", Message = $"Couldn't load the module: {ex.GetType().Name}: {ex.Message}" });
    return 1;
}
Send(new ModuleHostMessage { Type = "ready", Message = module.Name });

// Requests run off the reader, so it can hand the app's answers to a check that is waiting for them.
CancellationTokenSource? running = null;
// A per-device module: the devices it last found, and the latest result of each device run in this host (for its one report).
IReadOnlyList<ModuleInstance>? devices = null;
var deviceResults = new System.Collections.Concurrent.ConcurrentDictionary<string, DiagnosticResult>(StringComparer.OrdinalIgnoreCase);
Task? refresh = null;
Task? availability = null;
while (input.ReadLine() is { } line)
{
    var request = ModuleHostMessage.Parse(line);
    if (request is null && !string.IsNullOrWhiteSpace(line)) Console.Error.WriteLine($"unreadable request ({line.Length} chars) ignored");
    switch (request?.Type)
    {
        case "answer":
            if (!queries.Complete(request)) Console.Error.WriteLine($"answer {request.Id} arrived with no query waiting for it");
            break;
        case "availability":
            // Every ask gets its own answer: the app reads one per ask, so a skipped one would leave the next ask reading a stale answer.
            var previous = availability;
            availability = Task.Run(async () =>
            {
                if (previous is not null) await previous.ConfigureAwait(false);
                try
                {
                    var a = await module.CheckAvailabilityAsync();
                    Send(new ModuleHostMessage { Type = "availability", Available = a.IsAvailable, Reason = a.Reason });
                }
                catch (Exception ex) { Send(new ModuleHostMessage { Type = "availability", Available = false, Reason = ex.Message }); }
            });
            break;
        case "refresh":
            if (refresh is { IsCompleted: false }) { Send(new ModuleHostMessage { Type = "error", Message = "already running" }); break; }
            running = new CancellationTokenSource();
            var ct = running.Token;
            var instance = request.Instance;
            refresh = Task.Run(async () =>
            {
                var progress = CheckProgressExtensions.Create(p => Send(new ModuleHostMessage { Type = "progress", Message = p.Message, Step = p.Step, Total = p.Total }));
                try
                {
                    DiagnosticResult r;
                    Dictionary<string, System.Text.Json.JsonElement>? pageData;
                    if (instance is not null && module is IPerDeviceModule perDevice)
                    {
                        r = await perDevice.RefreshAsync(instance, progress, ct);
                        deviceResults[instance.Key] = r with { InstanceKey = instance.Key, InstanceLabel = instance.Label };
                        // The devices as the module sees them now (a drive read is shared for a while, so this costs nothing after a run).
                        try { devices = (await perDevice.DetectAsync(ct)).Instances; } catch (Exception ex) when (ex is not OperationCanceledException) { }
                        pageData = ModulePageCalls.Write(module, devices, deviceResults);
                    }
                    else
                    {
                        r = await module.RefreshAsync(progress, ct);
                        pageData = ModulePageCalls.Write(module);
                    }
                    var other = r.Payload is AreaReport ? null : ModuleHostPayloads.Write(r.Payload);
                    Send(new ModuleHostMessage
                    {
                        Type = "result", Status = r.Status, Message = r.Message, Cancelled = r.Cancelled || ct.IsCancellationRequested, Report = r.Payload as AreaReport,
                        Payload = other?.Payload, PayloadType = other?.Type, PageData = pageData,
                    });
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    Send(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "Cancelled", Cancelled = true });
                }
                catch (Exception ex) { Send(new ModuleHostMessage { Type = "error", Message = $"{ex.GetType().Name}: {ex.Message}" }); }
            });
            break;
        case "detect":
            // A per-device module's devices (one run each). Answered off the reader: the module may ask the app for its drive list.
            _ = Task.Run(async () =>
            {
                try
                {
                    if (module is not IDetectableModule detectable) { Send(new ModuleHostMessage { Type = "detection", Reason = "This module doesn't run per device" }); return; }
                    var d = await detectable.DetectAsync();
                    devices = d.Instances;
                    Send(new ModuleHostMessage { Type = "detection", Reason = d.NotApplicableReason, Instances = [.. d.Instances] });
                }
                catch (Exception ex) { Send(new ModuleHostMessage { Type = "detection", Reason = $"Detection failed: {ex.Message}" }); }
            });
            break;
        case "call":
            // A click on the module's page that needs the module (ModulePageCalls), answered with "return" and the call's id. The app
            // sends one at a time and never during a run; the module's host queries are answered meanwhile.
            var call = request;
            _ = Task.Run(async () =>
            {
                try
                {
                    var value = await ModulePageCalls.InvokeAsync(module, call.Name ?? "", call.Args, CancellationToken.None);
                    Send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = true, Value = value });
                }
                catch (NotSupportedException ex) { Send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = false, Error = "unknown", Reason = ex.Message }); }
                catch (Exception ex) { Send(new ModuleHostMessage { Type = "return", Id = call.Id, Ok = false, Error = "failed", Reason = $"{ex.GetType().Name}: {ex.Message}" }); }
            });
            break;
        case "stop":
            try { running?.Cancel(); } catch (ObjectDisposedException) { }
            break;
        case "exit":
            return 0;
    }
}
queries.FailAll("the app closed the module host");
try { running?.Cancel(); } catch { }
return 0;
